# ------------------------------------------------------------
from datetime import datetime
import sys, copy, pyshark, threading, binascii, hashlib, json, logging
from aioquic.tls import CipherSuite, cipher_suite_hash, hkdf_expand_label, hkdf_extract
from aioquic.quic.quic_datagram_decomposer import quic_length_decoder, quic_datagram_decomposer_capture
from Crypto.Cipher import AES

INITIAL_SALT_VERSION_1  = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_CIPHER_SUITE    = CipherSuite.AES_128_GCM_SHA256
ALGORITHM               = cipher_suite_hash(INITIAL_CIPHER_SUITE)
PACKET_NUMBER_LENGTH    = 0
STREAM_HEADER           = 4

udp_streams     = {}
now             = str(datetime.timestamp(datetime.now())).split(".")[0]
interface       = sys.argv[1] if len(sys.argv)>1 else 'lo'
status          = {}
threads         = list()

# ------------------------------------------------------------


# TODO: Come trovare la richiesta HTTP3 - contare l'ordine dei pacchetti da ambo i lati,
# dopo l'ack del ServerFinished ho il pacchetto con la richiesta http3

# TODO: PULIZIA VARIABILI MPS



def toBytes(hex_string):
    return(bytes.fromhex(hex_string.replace(':','')))


def get_tail_minus_36(transcript: str) -> str:

    output              = ''

    length              = int( len(transcript) / 2 )
    num_whole_blocks    = int( ( length - 36 ) / 64 )
    tail_len            = length - num_whole_blocks * 64

    for i in range(0, tail_len):
        j = num_whole_blocks * 64 + i
        output += transcript[2*j : (2*j) + 2]

    return output


def derive_initial_secrets(packet):

    dcid            = toBytes(packet.quic.dcid)
    initial_secret  = hkdf_extract(ALGORITHM, INITIAL_SALT_VERSION_1, dcid)

    client_initial_secret   = hkdf_expand_label(ALGORITHM, initial_secret, b"client in", b"", ALGORITHM.digest_size)
    server_initial_secret   = hkdf_expand_label(ALGORITHM, initial_secret, b"server in", b"", ALGORITHM.digest_size)

    return client_initial_secret, server_initial_secret


def decrypt_payload(packet, secret):
    global PACKET_NUMBER_LENGTH

    quic_raw_packet      = toBytes(packet.udp.payload)
    crypto_raw_packet    = toBytes(packet.quic.payload)

    # print('QUIC Packet:', quic_raw_packet.hex(), '\n')
    # print('QUIC Payload:', crypto_raw_packet[:len(crypto_raw_packet)-16].hex(), crypto_raw_packet[-16:].hex(), '\n')

    quic_hp         = hkdf_expand_label(ALGORITHM, secret, b"quic hp", b"", 16)

    if packet.quic.header_form == '1': # Long Header
        pn_offset   = 7 + int(packet.quic.dcil) + int(packet.quic.scil) + 2
        if packet.quic.long_packet_type == '0': # Initial Packet
            if packet.quic.token_length != '0':
                pn_offset += int(packet.quic.token_length) + quic_length_decoder(crypto_raw_packet[pn_offset])
            else:
                pn_offset += 1
    else: # Short Header
        pn_offset   = 1 + int(packet.quic.dcil)

    if packet.quic.packet_number_length == '1':
        PACKET_NUMBER_LENGTH = 2

    sample_offset   = pn_offset + PACKET_NUMBER_LENGTH

    quic_header = quic_raw_packet[:sample_offset]
    # print('QUIC Header:', quic_header.hex(), '\n') # ca 00000001 08 43c0b705938c1aff 08 a862bd5bf12a3a75 00 4496 5a34

    ''' DA VERIFICARE -------------------------------------------------------------------------------------------------------------------------
    sample_payload = quic_raw_packet[sample_offset:sample_offset+16]
    print('Sample:', sample_payload.hex(), '\n')

    header_encryptor = AES.new(quic_hp, AES.MODE_ECB)
    mask = header_encryptor.encrypt(sample_payload)
    print('MASK:', mask.hex(), '\n')

    # c10000000108a7d73d003ff2bb7f0815c8b4101d3a26960044960000
    # c40000000108a7d73d003ff2bb7f0815c8b4101d3a2696004496ef86

    # First byte contains packet number length
    print('First Byte:', ''.join(format(byte, '08b') for byte in bytes.fromhex(quic_raw_packet.hex()))[:8], '\n')
    print('Mask:', ''.join(format(byte, '08b') for byte in bytes.fromhex(mask.hex()))[:8], '\n')
    print('Mask & 0x0f:', ''.join(format(byte, '08b') for byte in bytes.fromhex(hex(mask[0] & 0x0f).replace('x','')))[:8], '\n')
    first_byte = quic_raw_packet[0] ^ (mask[0] & 0x0f)
    print('First Byte decoded:', ''.join(format(byte, '08b') for byte in bytes.fromhex(hex(first_byte).replace('0x','')))[:8], '\n')
    pnl = (first_byte & 0x03) + 1
    print('PNL:', ''.join(format(byte, '08b') for byte in bytes.fromhex(hex(pnl).replace('x','')))[:8], '\n')

    encrypted_pn = quic_raw_packet[pn_offset:pn_offset+pnl]
    print('Encrypted PN:', ''.join(format(byte, '08b') for byte in bytes.fromhex(encrypted_pn.hex()))[:16])
    print('Related Mask:', ''.join(format(byte, '08b') for byte in bytes.fromhex(mask.hex()[2:pnl*2 + 2]))[:16])
    pn = bytes(map(operator.xor, encrypted_pn, mask[1:pnl + 1]))
    print('Decrypted PN:', ''.join(format(byte, '08b') for byte in bytes.fromhex(pn.hex()))[:16], '\n')
    --------------------------------------------------------------------------------------------------------------------------------------- '''
    
    pn = bytes.fromhex(hex(int(packet.quic.packet_number)).replace('x','').ljust(PACKET_NUMBER_LENGTH*2, '0'))
    # print('Packet Number:', pn.hex(), '\n')

    pp_key = hkdf_expand_label(ALGORITHM, secret, b"quic key", b"", 16)
    pre_iv = hkdf_expand_label(ALGORITHM, secret, b"quic iv", b"", 12)
    iv = (int.from_bytes(pre_iv, "big") ^ int.from_bytes(pn, "big")).to_bytes(12, "big")

    payload_encryptor = AES.new(pp_key, AES.MODE_GCM, iv)
    payload_encryptor.update(quic_header[:pn_offset] + pn)
    # payload = payload_encryptor.decrypt_and_verify(crypto_raw_packet[:len(crypto_raw_packet)-16], crypto_raw_packet[-16:])
    payload = payload_encryptor.decrypt(crypto_raw_packet[:len(crypto_raw_packet)-16]) #Withoud AEAD Tag

    return payload



def prepare_parameters(packets_transcript_json_capture, stream_id):
    
    params = {}

    # Plaintext

    params['client_hello'] = { 
        'plaintext': packets_transcript_json_capture['CLIENT-ClientHello']['plaintext'],
        'ciphertext': packets_transcript_json_capture['CLIENT-ClientHello']['ciphertext'],
        'length': packets_transcript_json_capture['CLIENT-ClientHello']['length']
    }

    params['server_hello'] = { 
        'plaintext': packets_transcript_json_capture['SERVER-ServerHello']['plaintext'],
        'ciphertext': packets_transcript_json_capture['SERVER-ServerHello']['ciphertext'],
        'length': packets_transcript_json_capture['SERVER-ServerHello']['length']
    }

    params['client_server_hello'] = { 
        'transcript': params['client_hello']['plaintext'] + params['server_hello']['plaintext'], # ch_sh = pt2_line
        'length': params['client_hello']['length'] + params['server_hello']['length'],
    }
    params['client_server_hello']['hash'] = hashlib.sha256(bytes.fromhex(params['client_server_hello']['transcript'])).digest().hex() # H2 
    

    # Ciphertext

    params['server_finished'] = { 
        'ciphertext': packets_transcript_json_capture['HANDSHAKE-PACKETS'][-1]['ciphertext'][len(packets_transcript_json_capture['HANDSHAKE-PACKETS'][-1]['ciphertext'])-72:]
    }

    params['extensions_certificate_certificatevrfy_serverfinished'] = { 
        'transcript': ''.join(elem['ciphertext'] for elem in packets_transcript_json_capture['HANDSHAKE-PACKETS']), # ct3_line
        'length': int(len(''.join(elem['ciphertext'] for elem in packets_transcript_json_capture['HANDSHAKE-PACKETS'])) / 2)
    }

    params['handshake'] = {
        'transcript': params['client_server_hello']['transcript'] + params['extensions_certificate_certificatevrfy_serverfinished']['transcript'],
        'length': params['client_server_hello']['length'] + params['extensions_certificate_certificatevrfy_serverfinished']['length'], # TR3_len
    }

    handshake_tail = get_tail_minus_36(params['handshake']['transcript'])
    params['handshake']['tail'] = handshake_tail[0 : int(len(handshake_tail) - 72)] # 28 byte per completare il blocco con i primi 4 bytes del Server Finished (sha256)
    params['handshake']['tail_length'] = int( len(params['handshake']['tail']) / 2 )
    params['handshake']['tail_head'] = str(packets_transcript_json_capture['HANDSHAKE-PACKETS'][-1]['CRYPTO-Frame']).split(params['handshake']['tail'])[0] # Compute the head (in the Record Layer) before the tail
    params['handshake']['tail_head_length'] = int( len(params['handshake']['tail_head']) / 2 )

    params['http3'] = {}
    params['http3']['request'] = {
        'ciphertext': packets_transcript_json_capture['HTTP3-REQUEST']['ciphertext'],
        'length': packets_transcript_json_capture['HTTP3-REQUEST']['length'],
    }
    params['http3']['request']['head'] = str(packets_transcript_json_capture['HTTP3-REQUEST']['STREAM-Frame']).split(params['http3']['request']['ciphertext'])[0]
    params['http3']['request']['head_length'] = int( len(params['http3']['request']['head']) / 2 )


    with open('./files/params.json', 'w') as f:
        json.dump(params, f, indent=2)


    with open('./files/params.txt', 'w') as f:
        f.write('0'*32                                                                          + '\n') # HS (Witness)
        f.write(params['client_server_hello']['hash']                                           + '\n') # H_2
        f.write(params['client_server_hello']['transcript']                                     + '\n') # PT_2
        f.write(params['handshake']['tail']                                                     + '\n') # Certificate Verify Tail
        f.write(params['server_finished']['ciphertext']                                         + '\n') # Server Finished
        f.write(params['extensions_certificate_certificatevrfy_serverfinished']['transcript']   + '\n') # CT_3
        f.write(params['http3']['request']['ciphertext']                                        + '\n') # HTTP3 Request
        # f.write(params['http3']['request']['head'] + params['http3']['request']['ciphertext']   + '\n') # HTTP3 Request (FULL)
        f.write('0'*32                                                                          + '\n') # H_state_tr7 (Witness)
        f.write(params['handshake']['transcript']                                               + '\n') # TR_3
        f.write(str(params['handshake']['tail_head_length'])                                    + '\n') # Certificate Verify Tail Head Length
        f.write('0'*32                                                                          + '\n') # HTTP3 Request Head Length (Witness)
        # f.write('0'*32                                                                          + '\n') # Path poisition in Request (Witness)

    print('- [', stream_id, '] Parameters saved\n\n')



def process_with_pyshark(fileName):
    global PACKET_NUMBER_LENGTH

    seen_packets = {'CH': False, 'SH': False, 'SH_ACK': False, 'EE-Cert-CertVrfy': False, 'EE-Cert-CertVrfy_ACK': False, 'CertVrfy-SF': False, 'CertVrfy-SF_ACK': False, 'HTTP3-REQUEST': False}

    client_connection_id    = b''
    server_connection_id    = b''
    initial                 = True
    packets_transcript_json_capture = {}

    # pcap_data = pyshark.FileCapture(fileName)
    # pcap_data_raw = pyshark.FileCapture(fileName, use_json=True, include_raw=True)
    capture=pyshark.LiveCapture(interface, bpf_filter="udp", output_file="./files/capture.pcapng")


    #scan all packets in the capture
    # for packet in pcap_data:
    for packet in capture.sniff_continuously():

        if 'udp' in packet:
            stream_id = packet.udp.stream
            if stream_id not in udp_streams:
                print('[', stream_id, '] New stream')
                udp_streams[stream_id] = []
                status[stream_id] = copy.deepcopy(seen_packets)
            udp_streams[stream_id].append(packet)

            if 'quic' in packet:

                if status[stream_id]['HTTP3-REQUEST'] == True:
                    status[stream_id]['HTTP3-REQUEST']  = False
                    packets_transcript_json_capture     = {}
                    initial                             = True
                    # print(status[stream_id], '\n')
                    print("\n\n*****************************************************************************************************************************************************************************\n\n")

                # for layer in packet.layers:
                # print(packet.udp, '\n\n')
                layer = packet.quic

                if hasattr(layer, 'packet_length'):
                    
                    # print(layer._all_fields, '\n\n')

                    for k,v in status[stream_id].items():
                        if v == False and k != 'HTTP3-REQUEST':
                            break
                    else:


                        encrypted_payload   = layer.payload if hasattr(layer, 'payload') else layer.remaining_payload
                        stream_payload      = toBytes(encrypted_payload)[PACKET_NUMBER_LENGTH:int(len(toBytes(encrypted_payload)))-16]
                        encrypted_payload   = toBytes(encrypted_payload)[PACKET_NUMBER_LENGTH+STREAM_HEADER:int(len(toBytes(encrypted_payload)))-16]

                        # print("HTTP3 REQUEST -", encrypted_payload.hex(), '\n\n')
                        print('+ [', stream_id, '] HTTP3 REQUEST')


                        packets_transcript_json_capture['HTTP3-REQUEST'] = {
                            'length': len(encrypted_payload),
                            'ciphertext': encrypted_payload.hex(),
                            'STREAM-Frame': stream_payload.hex()
                        }

                        status[stream_id]['CH']                      = False
                        status[stream_id]['SH']                      = False
                        status[stream_id]['SH_ACK']                  = False
                        status[stream_id]['EE-Cert-CertVrfy']        = False
                        status[stream_id]['EE-Cert-CertVrfy_ACK']    = False
                        status[stream_id]['CertVrfy-SF']             = False
                        status[stream_id]['CertVrfy-SF_ACK']         = False
                        status[stream_id]['HTTP3-REQUEST']           = True

                        try:
                            prepare_parameters(packets_transcript_json_capture, stream_id)
                        except KeyError as ke:
                            print("Error in prepare_parameters:", ke, '---> RESET\n')
                            

                    if hasattr(layer, 'long_packet_type'):
                        
                        match(layer.long_packet_type):

                            case '0': # Initial Packet
                            
                                if hasattr(layer, 'tls_handshake_type'):
                                
                                    if initial:
                                        client_initial_secret, server_initial_secret = derive_initial_secrets(packet)
                                        initial = False


                                    if layer.tls_handshake_type == '1': # Client Hello
                                        # print("Client Hello -", packet, '~'*100, '\n')
                                        secret                  = client_initial_secret
                                        peer                    = ' CLIENT '
                                        client_connection_id    = toBytes(packet.quic.scid)
                                        status[stream_id]['CH'] = True
                                        print('+ [', stream_id, '] CLIENT HELLO')
                                    
                                    elif layer.tls_handshake_type == '2': # Server Hello
                                        # print("Server Hello -", packet, '~'*100, '\n')
                                        secret                  = server_initial_secret
                                        peer                    = ' SERVER '
                                        server_connection_id    = toBytes(packet.quic.scid)
                                        status[stream_id]['SH'] = True
                                        print('+ [', stream_id, '] SERVER HELLO')


                                    encrypted_payload = toBytes(layer.payload)[:int(len(toBytes(layer.payload)))-16]
                                    # print("Encrypted Payload -", toBytes(layer.payload)[:int(len(toBytes(layer.payload)))-16].hex(), '\n\n')
                                    decrypted_payload = decrypt_payload(packet, secret)
                                    # print("Decrypted Payload -", decrypted_payload.hex(), '\n', '~'*100, '\n')

                                    # ack, crypto, padding, stream, connection_close
                                    quic_frames = []
                                    if hasattr(layer, 'ack_ack_delay'):
                                        quic_frames.append({'frame_type': 'ack'})
                                    if hasattr(layer, 'crypto_length'):
                                        quic_frames.append({'frame_type': 'crypto', 'length': int(layer.crypto_length), 'offset': int(layer.crypto_offset)})
                                    if hasattr(layer, 'padding_length'):
                                        quic_frames.append({'frame_type': 'padding'})

                                    # print(quic_frames)
                                    
                                    packets_transcript_json_capture = quic_datagram_decomposer_capture(peer, quic_frames, decrypted_payload, encrypted_payload, packets_transcript_json_capture)
                                    # print(packets_transcript_json_capture, '\n')

                                else:
                                    status[stream_id]['SH_ACK']    = True
                                    print('+ [', stream_id, '] SERVER HELLO ACK')

                            case '2': # Handshake Packet
                                # print(layer._all_fields, '\n\n')

                                if toBytes(packet.quic.scid).hex() == server_connection_id.hex():
                                
                                    encrypted_payload = layer.payload if hasattr(layer, 'payload') else layer.remaining_payload
                                    encrypted_payload = toBytes(encrypted_payload)[PACKET_NUMBER_LENGTH:int(len(toBytes(encrypted_payload)))-16]

                                    # print("Handshake Packet -", encrypted_payload.hex(), '\n\n')
                                    
                                    try:
                                        packets_transcript_json_capture['HANDSHAKE-PACKETS'].append({
                                            'length': len(encrypted_payload[5:]),               # CRYPTO HEADER di 5 byte perché: Offset nel CRYPTO Header è 1153 (codificato con 2 bytes), mentre length dipende dalla lunghezza del certificato (controllare qual è la dimensione minima)
                                            'ciphertext': encrypted_payload[5:].hex(),
                                            'CRYPTO-Frame': encrypted_payload.hex()
                                        })
                                        status[stream_id]['CertVrfy-SF']    = True
                                        print('+ [', stream_id, '] CertVrfy-SF')
                                    except:
                                        packets_transcript_json_capture['HANDSHAKE-PACKETS'] = []
                                        packets_transcript_json_capture['HANDSHAKE-PACKETS'].append({
                                            'length': len(encrypted_payload[4:]),               # CRYPTO HEADER di 4 byte perché: QUIC riempie il pacchetto a 1200 byte e quindi CRYPTO Payload è di 1153 (lenght codificato con 2 bytes e offset 1 byte) 
                                            'ciphertext': encrypted_payload[4:].hex()
                                        })
                                        status[stream_id]['EE-Cert-CertVrfy']    = True
                                        print('+ [', stream_id, '] EE-Cert-CertVrfy')
                                
                                elif toBytes(packet.quic.scid).hex() == client_connection_id.hex():
                                        
                                    if status[stream_id]['EE-Cert-CertVrfy_ACK'] == True:
                                        status[stream_id]['CertVrfy-SF_ACK']         = True
                                        print('+ [', stream_id, '] CertVrfy-SF ACK')
                                    else:
                                        status[stream_id]['EE-Cert-CertVrfy_ACK']    = True
                                        print('+ [', stream_id, '] EE-Cert-CertVrfy ACK')
                                
                # print(status[stream_id], '\n')
                # print("\n*****************************************************************************************************************************************************************************\n\n\n")
    


if __name__ == "__main__":

    try:
        verbose = True if sys.argv[2] == 'v' else False            
    except IndexError:
        verbose = False

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if verbose else logging.INFO,
    )

    print("STARTING CAPTURE . . .\n\n")
    # pcap_file = "./files/quic_exchange.pcap"
    pcap_file = "./files/capture.pcapng"
    capturer = threading.Thread(target=process_with_pyshark, args=(pcap_file,))
    threads.append(capturer)
    capturer.start()