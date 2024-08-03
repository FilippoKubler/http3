import argparse, asyncio, logging, os, pickle, ssl, time, json, copy, subprocess, urllib.parse, pylsqpack, requests, sha2_compressions, hashlib, sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from middlebox.trackers import *

from collections import deque
from typing import BinaryIO, Callable, Deque, Dict, List, Optional, Union, cast
from urllib.parse import urlparse

import aioquic
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.logger import QuicFileLogger
from aioquic.tls import CipherSuite, SessionTicket

try:
    import uvloop # type: ignore
except ImportError:
    uvloop = None


from huffman import huffman_encoding, huffman_decoding

logger = logging.getLogger("client")

HttpConnection = Union[H0Connection, H3Connection]

USER_AGENT = "aioquic/" + aioquic.__version__




def get_tail_minus_36(transcript: str) -> str:

    output              = ''

    length              = int( len(transcript) / 2 )
    num_whole_blocks    = int( ( length - 36 ) / 64 )
    tail_len            = length - num_whole_blocks * 64

    for i in range(0, tail_len):
        j = num_whole_blocks * 64 + i
        output += transcript[2*j : (2*j) + 2]

    return output


def find_path_position(request: str, path_encoding: str):
    try:
        return request.index(path_encoding)
    except ValueError:
        return -1


def get_prover_key(test):

    c = 0
    while True:
        try:
            if test:
                start_time  = time.time()
                outputs     = [["Request sent", time.time()-start_time, 0]]
                memory      = [[0, time.time()-start_time, 0]]

            response_key = requests.get("http://127.0.0.1:5001/prover-key")
            # response_params = requests.get("http://127.0.0.1:5001/parameters")
        except requests.ConnectionError:
            c+=1
            if c==1: 
                print("Retrying until the IDS goes online...")
            time.sleep(2)
            continue
        print("Connected to IDS!")
        break

    with open('files/provKey.bin', 'wb') as file:
        file.write(response_key.content)

    print("\n\n[+] Prover Key received!\n\n")

    if test:
        outputs += [["Prover Key received", time.time()-start_time, 0]]
        memory  += [[0, time.time()-start_time, 0]]
        return start_time, outputs, memory

    return 0, 0, 0


def send_generated_proof(client_random, test, start_time, outputs, memory):

    if test:
        outputs     += [["Proof Request sent", time.time()-start_time, 0]]
        memory      += [[0, time.time()-start_time, 0]]

    with open(f'files/proof{client_random}1.bin', 'rb') as file:
        response = requests.post("http://127.0.0.1:5001/prove", files={'proof': file}, headers={'Client-Random': client_random})
        if response.status_code == 200:
            print("File sent successfully.")
        else:
            print("Error sending file. Status code:", response.status_code)

    print("\n\n[+] Proof sent!\n\n")

    if test:
        outputs += [["Proof sent", time.time()-start_time, 0]]
        memory  += [[0, time.time()-start_time, 0]]
        return outputs, memory
    
    return 0, 0





class URL:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)

        self.authority = parsed.netloc
        self.full_path = parsed.path or "/"
        if parsed.query:
            self.full_path += "?" + parsed.query
        self.scheme = parsed.scheme


class HttpRequest:
    def __init__(
        self,
        method: str,
        url: URL,
        content: bytes = b"",
        headers: Optional[Dict] = None,
    ) -> None:
        if headers is None:
            headers = {}

        self.content = content
        self.headers = headers
        self.method = method
        self.url = url


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.pushes: Dict[int, Deque[H3Event]] = {}
        self._http: Optional[HttpConnection] = None
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}

        if self._quic.configuration.alpn_protocols[0].startswith("hq-"):
            self._http = H0Connection(self._quic)
        else:
            self._http = H3Connection(self._quic)

        self._client_random = ''
        self._allowed_url   = ''

    async def get(self, url: str, headers: Optional[Dict] = None) -> Deque[H3Event]:
        """
        Perform a GET request.
        """
        return await self._request(
            HttpRequest(method="GET", url=URL(url), headers=headers)
        )

    async def post(
        self, url: str, data: bytes, headers: Optional[Dict] = None
    ) -> Deque[H3Event]:
        """
        Perform a POST request.
        """
        return await self._request(
            HttpRequest(method="POST", url=URL(url), content=data, headers=headers)
        )

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(self._request_events.pop(stream_id))

            elif event.push_id in self.pushes:
                # push
                self.pushes[event.push_id].append(event)

        elif isinstance(event, PushPromiseReceived):
            self.pushes[event.push_id] = deque()
            self.pushes[event.push_id].append(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        #  pass event to the HTTP layer
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def _request(self, request: HttpRequest) -> Deque[H3Event]:
        stream_id = self._quic.get_next_available_stream_id()

        headers = [
            (b":method", request.method.encode()),
            (b":scheme", request.url.scheme.encode()),
            (b":authority", request.url.authority.encode()),
            (b":path", request.url.full_path.encode()),
            (b"user-agent", USER_AGENT.encode()),
        ] + [(k.encode(), v.encode()) for (k, v) in request.headers.items()] 
        # + [
        #     (b"pippo", b"pluto"),
        #     (b"pluto", b"pippo"),
        #     (b"jbfwdsfhbv", b"afskjdbgasbas"),
        #     (b"jbfwdsdasfdv", b"fdskn"),
        # ]

        self._http.send_headers(
            stream_id=stream_id,
            headers=headers,
            end_stream=not request.content,
        )

        if request.content:
            self._http.send_data(
                stream_id=stream_id, data=request.content, end_stream=True
            )

        self._http._http3_request = copy.deepcopy(self._quic._streams[stream_id].sender._buffer)

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()


        self._http._encoder = pylsqpack.Encoder()
        
        allowed_headers = [
            (b":method", request.method.encode()),
            (b":scheme", request.url.scheme.encode()),
            (b":authority", request.url.authority.encode()),
            (b":path", request.url.full_path.encode()),
        ]

        self._http._allowed_headers = self._http._encode_headers(stream_id, allowed_headers).hex()

        return await asyncio.shield(waiter)


async def perform_http_request(
    client: HttpClient,
    url: str,
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
    print_params: bool,
) -> None:

    # perform request
    start = time.time()
    if data is not None:
        data_bytes = data.encode()
        http_events = await client.post(
            url,
            data=data_bytes,
            headers={
                "content-length": str(len(data_bytes)),
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        method = "POST"
    else:
        http_events = await client.get(url)
        method = "GET"
    elapsed = time.time() - start

    print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print(f"Perform HTTP/3 {method} Request to {url}\n")


    print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print(f"Got HTTP/3 Response from {url}")
    # print speed
    octets = 0
    for http_event in http_events:

        if isinstance(http_event, HeadersReceived):
            print('\n'.join('{}: {}'.format(k.decode(), v.decode()) for k, v in http_event.headers))

        if isinstance(http_event, DataReceived):
            print(http_event.data.decode())
            octets += len(http_event.data)

    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")


    params = {}

    # Plaintext

    params['client_hello'] = { 
        'plaintext': client._quic.packets_transcript_json['CLIENT-ClientHello']['plaintext'],
        'ciphertext': client._quic.packets_transcript_json['CLIENT-ClientHello']['ciphertext'],
        'length': client._quic.packets_transcript_json['CLIENT-ClientHello']['length']
    }

    # while True:
    #     try:
    params['server_hello'] = { 
        'plaintext': client._quic.packets_transcript_json['SERVER-ServerHello']['plaintext'],
        'ciphertext': client._quic.packets_transcript_json['SERVER-ServerHello']['ciphertext'],
        'length': client._quic.packets_transcript_json['SERVER-ServerHello']['length']
    }
    #         break
    #     except KeyError:
    #         continue

    params['client_server_hello'] = { 
        'transcript': params['client_hello']['plaintext'] + params['server_hello']['plaintext'], # ch_sh = pt2_line
        'length': params['client_hello']['length'] + params['server_hello']['length'],
    }
    params['client_server_hello']['hash'] = hashlib.sha256(bytes.fromhex(params['client_server_hello']['transcript'])).digest().hex() # H2 


    # Ciphertext

    params['encrypted_extensions'] = {
        'plaintext': client._quic.packets_transcript_json['SERVER-EncryptedExtensions']['plaintext'],
        'ciphertext': client._quic.packets_transcript_json['SERVER-EncryptedExtensions']['ciphertext'],
        'length': client._quic.packets_transcript_json['SERVER-EncryptedExtensions']['length']
    }

    params['certificate'] = { 
        'plaintext': client._quic.packets_transcript_json['SERVER-Certificate']['plaintext'],
        'ciphertext': client._quic.packets_transcript_json['SERVER-Certificate']['ciphertext'],
        'length': client._quic.packets_transcript_json['SERVER-Certificate']['length']
    }

    params['certificate_verify'] = { 
        'plaintext': client._quic.packets_transcript_json['SERVER-CertificateVerify']['plaintext'],
        'ciphertext': client._quic.packets_transcript_json['SERVER-CertificateVerify']['ciphertext'],
        'length': client._quic.packets_transcript_json['SERVER-CertificateVerify']['length'],
        'H_state_tr7': sha2_compressions.get_H_state(params['client_server_hello']['transcript'] + params['encrypted_extensions']['plaintext'] + params['certificate']['plaintext'] + client._quic.packets_transcript_json['SERVER-CertificateVerify']['plaintext']) # H_state_tr7 - the H-state of SHA up to the last whole block of TR7
    }

    params['server_finished'] = {
        'plaintext': client._quic.packets_transcript_json['SERVER-Finished']['plaintext'],
        'ciphertext': client._quic.packets_transcript_json['SERVER-Finished']['ciphertext'], # 36 byte = 4 + 32
        'length': client._quic.packets_transcript_json['SERVER-Finished']['length']
    }

    params['extensions_certificate_certificatevrfy_serverfinished'] = { 
        'transcript': params['encrypted_extensions']['ciphertext'] + params['certificate']['ciphertext'] + params['certificate_verify']['ciphertext'] + params['server_finished']['ciphertext'], # ct3_line
        'length': params['encrypted_extensions']['length'] + params['certificate']['length'] + params['certificate_verify']['length'] + params['server_finished']['length']
    }

    params['handshake'] = {
        'transcript': params['client_server_hello']['transcript'] + params['extensions_certificate_certificatevrfy_serverfinished']['transcript'], # TR3 = CH || SH || ENCEXT || CERT || CERTVRFY || FINISHED (CH e SH in chiaro, gli altri cifrati)
        'length': params['client_server_hello']['length'] + params['extensions_certificate_certificatevrfy_serverfinished']['length'], # TR3_len
        'hash': hashlib.sha256(client._quic.tls._transcript).digest().hex(), # H3
        'secret': client._quic.tls._handshake_secret # HS
    }

    handshake_tail = get_tail_minus_36(params['handshake']['transcript'])
    params['certificate_verify']['tail'] = handshake_tail[0 : int(len(handshake_tail) - params['server_finished']['length']*2)] # 28 byte per completare il blocco con i primi 4 bytes del Server Finished (sha256)
    params['certificate_verify']['tail_length'] = int( len(params['certificate_verify']['tail']) / 2 )
    params['certificate_verify']['head'] = str(client._quic.packets_transcript_json['SERVER-CertificateVerify']['CRYPTO-Frame']).split(params['certificate_verify']['tail'])[0] # Compute the head (in the Record Layer) before the tail
    params['certificate_verify']['head_length'] = int( len(params['certificate_verify']['head']) / 2 )

    params['http3'] = {}
    params['http3']['request'] = {
        'plaintext': client._quic.packets_transcript_json['CLIENT-HTTP3 REQUEST']['plaintext'],
        'ciphertext': client._quic.packets_transcript_json['CLIENT-HTTP3 REQUEST']['ciphertext'],
        'length': client._quic.packets_transcript_json['CLIENT-HTTP3 REQUEST']['length'],         
    }
    params['http3']['request']['head'] = str(client._quic.packets_transcript_json['CLIENT-HTTP3 REQUEST']['STREAM-Frame']).split(params['http3']['request']['ciphertext'])[0]
    params['http3']['request']['head_length'] = int( len(params['http3']['request']['head']) / 2 )
    params['http3']['response'] = {
        'plaintext': client._quic.packets_transcript_json['SERVER-HTTP3 RESPONSE']['plaintext'],
        'ciphertext': client._quic.packets_transcript_json['SERVER-HTTP3 RESPONSE']['ciphertext'],
        'length': client._quic.packets_transcript_json['SERVER-HTTP3 RESPONSE']['length'],        
    }

    # TODO: da verificare se tenere il padding di huffman e come fare il match bit a bit (? = 1111111100, 8 bit a 1, il path sarà sempre "paddato" prima di eventuali parametri)
    path = urllib.parse.urlparse(url).path
    path_in_huffman, huffman_padding = huffman_encoding(path)
    print(f"Path: {path}", f"Huffman Path: {path_in_huffman}", f"Huffman Path not Padded: {path_in_huffman[:-int(huffman_padding/8)*2]}", sep='\n', end='\n\n')
    print(client._http._allowed_headers, client._http._allowed_headers[:-huffman_padding])

    params['http3']['request']['huffman_path_encoding'] = client._http._allowed_headers # [:-huffman_padding] # huffman_encoding(urllib.parse.urlparse(url).path)

    params['http3']['request']['path_position'] = int(find_path_position(params['http3']['request']['plaintext'], params['http3']['request']['huffman_path_encoding']) / 2)


    # client random = SCID + DCID
    client._client_random   = client._quic.host_cid.hex() + client._quic._peer_cid.cid.hex()
    # Allowed URL passed by middlebox
    client._allowed_url     = params['http3']['request']['huffman_path_encoding']


    # CLIENT Packet Encryption -> aioquic/quic/packet_builder.py:338 (_end_packet function)
    # SERVER Packet Decryption -> aioquic/quic/connection.py:1137 (receive_datagram function)

    if print_params:
        print()
        print(".........................  PARAMS  .........................")
        print(json.dumps(params, indent=2))
        print("."*60)
        print()
    else:
        with open('./files/params.json', 'w') as f:
            json.dump(params, f, indent=2)

    with open('./files/params.txt', 'w') as f:
        f.write(params['handshake']['secret']                                                   + '\n') # HS
        f.write(params['client_server_hello']['hash']                                           + '\n') # H_2
        f.write(params['client_server_hello']['transcript']                                     + '\n') # PT_2
        f.write(params['certificate_verify']['tail']                                            + '\n') # Certificate Verify Tail
        f.write(params['server_finished']['ciphertext']                                         + '\n') # Server Finished
        f.write(params['extensions_certificate_certificatevrfy_serverfinished']['transcript']   + '\n') # CT_3
        f.write(params['http3']['request']['ciphertext']                                        + '\n') # HTTP3 Request
        f.write(params['certificate_verify']['H_state_tr7']                                     + '\n') # H_state_tr7
        f.write(str(params['handshake']['transcript'])                                          + '\n') # TR_3
        f.write(str(params['certificate_verify']['head_length'])                                + '\n') # Certificate Verify Tail Head Length
        f.write(str(params['http3']['request']['head_length'])                                  + '\n') # HTTP3 Request Head Length
        # f.write(str(params['http3']['request']['path_position'])                                + '\n') # Path poisition in Request

        f.write('~'*10 + '    EXPECTED VALUES    ' + '~'*10 + '\n')
        f.write(f'Certificate Verify Length: {params["certificate_verify"]["length"]}\n')
        f.write(f'Certificate Verify Head Length: {params["certificate_verify"]["length"] - params["certificate_verify"]["tail_length"]}\n')
        f.write(f'Certificate Verify Tail Length: {params["certificate_verify"]["tail_length"]}\n')
        f.write(f'Server Finished Plaintext: {params["server_finished"]["plaintext"]}\n')
        f.write(f'H3: {params["handshake"]["hash"]}\n')
        f.write(f'Path Encoding: {params["http3"]["request"]["huffman_path_encoding"]}\n') # Huffman Path Encoding
        f.write(f'HTTP3 Request Plaintext: {params["http3"]["request"]["plaintext"]}\n')
        f.write(f'Server HS Secret: {client._quic.tls._server_handshake_secret}\n')
        f.write(f'Client AP Secret: {client._quic.tls._client_application_secret}\n')


    logger.info(
        "Response received for %s %s : %d bytes in %.1f s (%.3f Mbps)"
        % (method, urlparse(url).path, octets, elapsed, octets * 8 / elapsed / 1000000)
    )

    # output response
    if output_dir is not None:
        output_path = os.path.join(output_dir, os.path.basename(urlparse(url).path) or "index.html")
        with open(output_path, "wb") as output_file:
            write_response(http_events=http_events, include=include, output_file=output_file)


def process_http_pushes(
    client: HttpClient,
    include: bool,
    output_dir: Optional[str],
) -> None:
    for _, http_events in client.pushes.items():
        method = ""
        octets = 0
        path = ""
        for http_event in http_events:
            if isinstance(http_event, DataReceived):
                octets += len(http_event.data)
            elif isinstance(http_event, PushPromiseReceived):
                for header, value in http_event.headers:
                    if header == b":method":
                        method = value.decode()
                    elif header == b":path":
                        path = value.decode()
        logger.info("Push received for %s %s : %s bytes", method, path, octets)

        # output response
        if output_dir is not None:
            output_path = os.path.join(output_dir, os.path.basename(path) or "index.html")
            with open(output_path, "wb") as output_file:
                write_response(http_events=http_events, include=include, output_file=output_file)


def write_response(
    http_events: Deque[H3Event], output_file: BinaryIO, include: bool
) -> None:
    for http_event in http_events:
        if isinstance(http_event, HeadersReceived) and include:
            headers = b""
            for k, v in http_event.headers:
                headers += k + b": " + v + b"\r\n"
            if headers:
                output_file.write(headers + b"\r\n")
        elif isinstance(http_event, DataReceived):
            output_file.write(http_event.data)


def save_session_ticket(ticket: SessionTicket) -> None:
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


async def main(
    configuration: QuicConfiguration,
    urls: List[str],
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
    local_port: int,
    zero_rtt: bool,
    print_params: bool
) -> None:
    
    start_time, outputs, memory = get_prover_key(args.test)
    # get_parameters()

    # parse URL
    parsed = urlparse(urls[0])
    assert parsed.scheme in (
        "https",
    ), "Only https:// URLs are supported."
    host = parsed.hostname
    if parsed.port is not None:
        port = parsed.port
    else:
        port = 443

    # check validity of 2nd urls and later.
    for i in range(1, len(urls)):
        _p = urlparse(urls[i])

        # fill in if empty
        _scheme = _p.scheme or parsed.scheme
        _host = _p.hostname or host
        _port = _p.port or port

        assert _scheme == parsed.scheme, "URL scheme doesn't match"
        assert _host == host, "URL hostname doesn't match"
        assert _port == port, "URL port doesn't match"

        # reconstruct url with new hostname and port
        _p = _p._replace(scheme=_scheme)
        _p = _p._replace(netloc="{}:{}".format(_host, _port))
        _p = urlparse(_p.geturl())
        urls[i] = _p.geturl()

    if args.test:
        time_placeholder = time.time()-start_time

    async with connect(
        host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
        session_ticket_handler=save_session_ticket,
        local_port=local_port,
        wait_connected=not zero_rtt,
    ) as client:
        client = cast(HttpClient, client)

        if parsed.scheme == "https":
            # perform request
            coros = [
                perform_http_request(
                    client=client,
                    url=url,
                    data=data if args.data else None,
                    include=include,
                    output_dir=output_dir,
                    print_params=print_params,
                )
                for i, url in enumerate(urls)
            ]
            await asyncio.gather(*coros)

            # process http pushes
            process_http_pushes(client=client, include=include, output_dir=output_dir)
        client._quic.close(error_code=ErrorCode.H3_NO_ERROR)


    if args.test:

        out2        = [["Running circuit", time.time()-start_time, 0]]
        (out, mem, cpu_times)       = trackRun_cputime((f'java -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.HTTP3_String run ./files/params.txt {client._allowed_url} {client._client_random} 1').split(), "xjsnark_proofHTTP3_String", [start_time, 0])
        out         = out2 + out

        (out3, mem2, cpu_times2)    = trackRun_cputime((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/HTTP3_String.arith files/HTTP3_String_{client._client_random}1.in prove {client._client_random} 1').split(), "libsnark_proofHTTP3_String", [start_time, out[-1][2]])
        out         += out3
        mem         += mem2
        cpu_times   += cpu_times2

        for item in out:
            item[1] += time_placeholder
        for item in mem:
            item[1] += time_placeholder
        outputs += out
        memory  += mem

    else:
        subprocess.run((f'java -cp ../xjsnark_decompiled/backend_bin_mod/:../xjsnark_decompiled/xjsnark_bin/ xjsnark.PolicyCheck.HTTP3_String run ./files/params.txt {client._allowed_url} {client._client_random} 1').split())
        subprocess.run((f'../libsnark/build/libsnark/jsnark_interface/run_zkmb files/HTTP3_String.arith files/HTTP3_String_{client._client_random}1.in prove {client._client_random} 1').split())

    # perché non si contano i tempi anche nella send della proof?
    outputs, memory = send_generated_proof(client._client_random, args.test, start_time, outputs, memory)

    if args.test:
        os.makedirs(os.path.dirname(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/"), exist_ok=True)
        
        with open(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/cputime_HTTP3_String_libsnark_prove.json", 'w', encoding='utf-8') as f:
            json.dump(cpu_times, f, ensure_ascii=False, indent=4)
        with open(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/prove_HTTP3_String_output.json", 'w', encoding='utf-8') as f:
            json.dump(outputs, f, ensure_ascii=False, indent=4)
        with open(f"../Tests/outputs/full_simulations/HTTP3_String/run{str(args.run)}/prove_HTTP3_String_memory.json", 'w', encoding='utf-8') as f:
            json.dump(memory, f, ensure_ascii=False, indent=4)


if __name__ == "__main__":
    defaults = QuicConfiguration(is_client=True)

    parser = argparse.ArgumentParser(description="HTTP/3 client")
    parser.add_argument(
        "url", type=str, nargs="+", help="the URL to query (must be HTTPS)"
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )
    parser.add_argument(
        "--cipher-suites",
        type=str,
        help=(
            "only advertise the given cipher suites, e.g. `AES_256_GCM_SHA384,"
            "CHACHA20_POLY1305_SHA256`"
        ),
    )
    parser.add_argument(
        "--congestion-control-algorithm",
        type=str,
        default="reno",
        help="use the specified congestion control algorithm",
    )
    parser.add_argument(
        "-d", "--data", type=str, help="send the specified data in a POST request"
    )
    parser.add_argument(
        "-i",
        "--include",
        action="store_true",
        help="include the HTTP response headers in the output",
    )
    parser.add_argument(
        "--max-data",
        type=int,
        help="connection-wide flow control limit (default: %d)" % defaults.max_data,
    )
    parser.add_argument(
        "--max-stream-data",
        type=int,
        help="per-stream flow control limit (default: %d)" % defaults.max_stream_data,
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument("--legacy-http", action="store_true", help="use HTTP/0.9")
    parser.add_argument(
        "--output-dir",
        type=str,
        help="write downloaded files to this directory",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )
    parser.add_argument(
        "--local-port",
        type=int,
        default=0,
        help="local port to bind for connections",
    )
    parser.add_argument(
        "--max-datagram-size",
        type=int,
        default=defaults.max_datagram_size,
        help="maximum datagram size to send, excluding UDP or IP overhead",
    )
    parser.add_argument(
        "--zero-rtt", action="store_true", help="try to send requests using 0-RTT"
    )
    parser.add_argument(
        "--print-params", 
        action='store_true', 
        help="print or store TLS1.3 parameters"
    )
    parser.add_argument(
        "-t", "--test", action="store_true", help="run test mode"
    )
    parser.add_argument(
        "-r", "--run", type=int, default=0, help="run number"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    if args.output_dir is not None and not os.path.isdir(args.output_dir):
        raise Exception("%s is not a directory" % args.output_dir)

    # prepare configuration
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H0_ALPN if args.legacy_http else H3_ALPN,
        congestion_control_algorithm=args.congestion_control_algorithm,
        max_datagram_size=args.max_datagram_size,
    )
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.cipher_suites:
        configuration.cipher_suites = [
            CipherSuite[s] for s in args.cipher_suites.split(",")
        ]
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.max_data:
        configuration.max_data = args.max_data
    if args.max_stream_data:
        configuration.max_stream_data = args.max_stream_data
    if args.quic_log:
        configuration.quic_logger = QuicFileLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            pass


    if uvloop is not None:
        uvloop.install()
    asyncio.run(
        main(
            configuration=configuration,
            urls=args.url,
            data=args.data,
            include=args.include,
            output_dir=args.output_dir,
            local_port=args.local_port,
            zero_rtt=args.zero_rtt,
            print_params=True if args.print_params else False
        )
    )