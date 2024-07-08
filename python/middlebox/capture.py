import sys, copy, math, pyshark
from datetime import datetime
import threading


sessions = {}
status={}
tcp_streams={}
transcripts={}
threads = list()
append=False
interface=sys.argv[1] if len(sys.argv)>1 else 'lo'
#interface='lo'
now = str(datetime.timestamp(datetime.now())).split(".")[0]


# ------------------------------------------------------------

import binascii, hashlib, json
from aioquic.tls import CipherSuite, cipher_suite_hash, hkdf_expand_label, hkdf_extract
from aioquic.quic.quic_datagram_decomposer import quic_length_decoder, extract_tls13_handshake_type, quic_datagram_decomposer
from Crypto.Cipher import AES

INITIAL_SALT_VERSION_1  = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_CIPHER_SUITE    = CipherSuite.AES_128_GCM_SHA256
ALGORITHM               = cipher_suite_hash(INITIAL_CIPHER_SUITE)
PACKET_NUMBER_LENGTH    = 0

# ------------------------------------------------------------




def parseApplicationData(tls_data):
    #print(tls_data)
    msgs=[]
    offset = 0
    while offset < len(tls_data):
        content_type = int(tls_data[offset:offset+1].hex(), 16)
        record_length = int(tls_data[offset+3:offset+5].hex(), 16)
        tls_message = tls_data[offset+5:offset+5+record_length]
        '''
        # Process each TLS message separately based on the content type
        if content_type == 20:
            # ChangeCipherSpec message
            print("Parsed as ChangeCipherSpec:",record_length)
        elif content_type == 21:
            # Alert message
            print("Alert:")
        elif content_type == 22:
            # Handshake message
            print("Parsed as handshake:",record_length)
        elif content_type == 23:
            # Application Data message
            print("Parsed as Application Data:", record_length)
            #if(len(tls_message)<record_length):
            #    buffer=tls_message
            #print(tls_message.hex())
            #print("-----------------")
        else: print("Error parsing", content_type, record_length)
        '''
        msgs.append([content_type, tls_message])
        offset += record_length + 5
    return msgs        
        
def moreDataCondition(packet):
    #print(tcp_streams)
    if(len(tcp_streams[packet.tcp.stream])>1 
        and packet.tcp.dstport==tcp_streams[packet.tcp.stream][-1].tcp.dstport     #they are from the same direction 
        and int(packet.tcp.len)>0                                             #and not an ack/fin/syn...
        and packet.tcp.seq==tcp_streams[packet.tcp.stream][-2].tcp.nxtseq):     #and sequence numbers are adjacent
        return True
    else: return False

def getTail(servExt, ch_sh): #implements the get_tail_minus_36 from ChannelShortcut
    tot=ch_sh+servExt
    output = bytearray()
    tot_len = len(tot)
    whole_blocks = math.floor((tot_len - 36) / 64)
    tail_len = tot_len - whole_blocks * 64
    output=tot[whole_blocks*64:tot_len]
    return output

def printTranscript(transcripts):
    for id, transcript in transcripts.items():
        for k,v in transcript.items():
            print(k,": ",(v.hex() if isinstance(v, (bytearray, bytes)) else v))

def elaborateAppData(packet,stream_id):
    if status[packet.tcp.stream]["S_CS"] and not status[packet.tcp.stream]["SF"]: #it's still HANDSHAKE
        if (len(toBytes(packet.tls.app_data)) < 60): #set this to a reasonable lowerbound that includes Mandatory Extensions, min length Certificate + Verify and Finished (53)
            msgs=parseApplicationData(toBytes(packet.tcp.payload))
            if len(msgs)==6:
                status[packet.tcp.stream]["SF"] = True
                status[packet.tcp.stream]["src"]=packet.tcp.srcport
                status[packet.tcp.stream]["dst"]=packet.tcp.dstport
                print("Encrypted Ext + Certificate + Server Finished")
            else:
                print("Error")
            handshake_ct = bytearray()
            transcripts[packet.tcp.stream]['ServExt_ct_EncExt']=msgs[2][1][:-17]
            transcripts[packet.tcp.stream]['ServExt_ct_Cert']=msgs[3][1][:-17]
            transcripts[packet.tcp.stream]['ServExt_ct_CertVerify']=msgs[4][1][:-17]
            transcripts[packet.tcp.stream]['ServExt_ct_SF']=msgs[5][1][:-17]
            for msg in msgs[2:]:
                handshake_ct+=msg[1][:-17]
#            handshake_ct = handshake_ct[:-1]
            transcripts[packet.tcp.stream]['ServExt_ct']=handshake_ct
            transcripts[packet.tcp.stream]['ServExt_ct_len']=len(handshake_ct)
            transcripts[packet.tcp.stream]['ServExt_ct_tail']=getTail(handshake_ct, transcripts[packet.tcp.stream]['ch_sh'])
            print("Is this less than 48? -> ",math.floor((len(transcripts[packet.tcp.stream]['ServExt_ct'])-36)/64))
            print("Tail: ",len(transcripts[packet.tcp.stream]['ServExt_ct_tail']))
        else: #there is only one appData record layer
            print("Server Finished")
            handshake_ct=toBytes(packet.tls.app_data)
            #assume SF is inside the big packet
            status[packet.tcp.stream]["SF"] = True
            status[packet.tcp.stream]["src"]=packet.tcp.srcport
            status[packet.tcp.stream]["dst"]=packet.tcp.dstport
            handshake_ct=handshake_ct[:-17]
            transcripts[packet.tcp.stream]['ServExt_ct']=handshake_ct
            transcripts[packet.tcp.stream]['ServExt_ct_len']=len(handshake_ct)
            transcripts[packet.tcp.stream]['ServExt_ct_tail']=getTail(handshake_ct, transcripts[packet.tcp.stream]['ch_sh'])
            
    elif status[packet.tcp.stream]["C_CS"] and not status[packet.tcp.stream]["CF"]: #it's still HANDSHAKE
        print("Client Finished")
        status[packet.tcp.stream]["CF"]=True 
        status[packet.tcp.stream]["src"]=packet.tcp.srcport
        status[packet.tcp.stream]["dst"]=packet.tcp.dstport
        print(status[packet.tcp.stream], transcripts[packet.tcp.stream])
    elif status[packet.tcp.stream]["CF"] and status[packet.tcp.stream]["src"]==packet.tcp.srcport: #app data after CF-> the request
        print("(",stream_id,") App Layer Request")
        transcripts[stream_id]["appl_ct"]=packet.tls.app_data
        transcripts[packet.tcp.stream]["appl_ct"]
        print(packet.tls.app_data)
        print("CIAO")

def print_transcript(transcript, stream_id):
    original_stdout = sys.stdout
    random_id = toBytes(transcript['RandomID']).hex()
    name = "transcript_"+random_id+str(transcript['PacketNumber'])+".txt" #OR we could use the unique stream_id...
    
    f = open("files/"+name, "w")
    sys.stdout = f
    print('0'*32)    #PSK
    print('0'*32)    #ec_sk
    print(transcript['Cx'].hex())
    print(transcript['Cy'].hex())
    print(transcript['Sx'].hex())
    print(transcript['Sy'].hex())    
    print('0'*32)    #HS (Witness)
    print(transcript['H2'].hex())
    print('0'*32) #H7
    print('0'*32)    #H3
    print('0'*32)    #SF
    print(transcript['ch_sh'].hex())
    #print(transcript['ServExt_ct'].hex())
    print(transcript['ServExt_ct_EncExt'].hex())
    print(transcript['ServExt_ct_Cert'].hex())
    print(transcript['ServExt_ct_CertVerify'].hex())
    print(transcript['ServExt_ct_SF'].hex())
    print(transcript['appl_ct'].hex())
    print('0'*32)    # sha state
    print(transcript['PacketNumber'])    #TODO IMPLEMENT IN CIRCUIT
    print('0'*32)
    f.close()
    sys.stdout = original_stdout
    return name




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


def prepare_parameters(packets_transcript_json):
    
    params = {}

    # Plaintext
    params['client_hello'] = { 
        'plaintext': packets_transcript_json['CLIENT-ClientHello']['plaintext'],
        'ciphertext': packets_transcript_json['CLIENT-ClientHello']['ciphertext'],
        'length': packets_transcript_json['CLIENT-ClientHello']['length']
    }

    params['server_hello'] = { 
        'plaintext': packets_transcript_json['SERVER-ServerHello']['plaintext'],
        'ciphertext': packets_transcript_json['SERVER-ServerHello']['ciphertext'],
        'length': packets_transcript_json['SERVER-ServerHello']['length']
    }

    params['client_server_hello'] = { 
        'transcript': params['client_hello']['plaintext'] + params['server_hello']['plaintext'], # ch_sh = pt2_line
        'length': params['client_hello']['length'] + params['server_hello']['length'],
    }
    params['client_server_hello']['hash'] = hashlib.sha256(bytes.fromhex(params['client_server_hello']['transcript'])).digest().hex() # H2 
    
    # Ciphertext
    params['extensions_certificate_certificatevrfy_serverfinished'] = { 
        'transcript': ''.join(elem['ciphertext'] for elem in packets_transcript_json['HANDSHAKE-PACKETS']), # ct3_line
        'length': int(len(''.join(elem['ciphertext'] for elem in packets_transcript_json['HANDSHAKE-PACKETS'])) / 2)
    }

    params['handshake'] = {
        'transcript': params['client_server_hello']['transcript'] + params['extensions_certificate_certificatevrfy_serverfinished']['transcript'],
        'length': params['client_server_hello']['length'] + params['extensions_certificate_certificatevrfy_serverfinished']['length'], # TR3_len
    }

    handshake_tail = get_tail_minus_36(params['handshake']['transcript'])
    params['handshake']['tail'] = handshake_tail[0 : int(len(handshake_tail) - 72)] # 28 byte per completare il blocco con i primi 4 bytes del Server Finished (sha256)
    params['handshake']['tail_length'] = int( len(params['handshake']['tail']) / 2 )


    with open('params.json', 'w') as f:
        json.dump(params, f, indent=2)


    with open('params.txt', 'w') as f:
        f.write('0'*32                                                                          + '\n') # HS
        f.write(params['client_server_hello']['hash']                                           + '\n') # H_2
        f.write(params['client_server_hello']['transcript']                                     + '\n') # PT_2
        f.write('0'*32                                                                          + '\n') # Certificate Verify
        f.write(params['handshake']['tail']                                                     + '\n') # Certificate Verify Tail
        f.write('0'*32                                                                          + '\n') # Server Finished
        f.write(params['extensions_certificate_certificatevrfy_serverfinished']['transcript']   + '\n') # CT_3
        #f.write(params['http3']['request']['ciphertext']                                        + '\n') # HTTP3 Request
        f.write('0'*32                                                                          + '\n') # H_state_tr7
        f.write(params['handshake']['transcript']                                               + '\n') # TR_3
        f.write('0'*32                                                                          + '\n') # Certificate Verify Tail Head Length
        f.write('0'*32                                                                          + '\n') # HTTP3 Request Head Length
        f.write('0'*32                                                                          + '\n') # Path poisition in Request



def process_with_pyshark(fileName):
    global PACKET_NUMBER_LENGTH

    # tls_session={"CH": False, "SH": False, "S_CS": False, "SF": False, "C_CS": False, "CF": False, "App": 0, "src": '', "dst": ''}
    # transcript={"RandomID": '', "Cx":'', "Cy":'', "Sx":'', "Sy":'', "ch_sh":'', "ch_sh_len":'',"H2":'',"ServExt_ct":'', "ServExt_ct_EncExt":'',"ServExt_ct_Cert":'',"ServExt_ct_CertVerify":'',"ServExt_ct_SF":'', "ServExt_ct_tail":'', "appl_ct":'', "PacketNumber": '' }
    # ch_sh = bytearray()
    

    server_connection_id    = b''
    initial                 = True

    pcap_data = pyshark.FileCapture(fileName)
    # pcap_data_raw = pyshark.FileCapture(fileName, use_json=True, include_raw=True)
    # capture=pyshark.LiveCapture(interface, bpf_filter="udp", output_file="capture.pcapng")


    #scan all packets in the capture
    for packet in pcap_data:
    # for packet in capture.sniff_continuously():
        for layer in packet.layers:

            if hasattr(layer, 'packet_length'):
                
                # print(layer._all_fields, '\n\n')

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


                                if layer.tls_handshake_type == '2': # Server Hello
                                    # print("Server Hello -", packet, '~'*100, '\n')
                                    secret                  = server_initial_secret
                                    peer                    = ' SERVER '
                                    server_connection_id    = toBytes(packet.quic.scid)

                                
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

                                print(quic_frames)

                                packets_transcript_json = quic_datagram_decomposer(peer, quic_frames, decrypted_payload, encrypted_payload)

                        case '2': # Handshake Packet
                            print(layer._all_fields, '\n\n')

                            if toBytes(packet.quic.scid).hex() == server_connection_id.hex():
                            
                                encrypted_payload = layer.payload if hasattr(layer, 'payload') else layer.remaining_payload
                                encrypted_payload = toBytes(encrypted_payload)[PACKET_NUMBER_LENGTH:int(len(toBytes(encrypted_payload)))-16]

                                print("Handshake Packet -", encrypted_payload.hex(), '\n\n')
                                
                                try:
                                    packets_transcript_json['HANDSHAKE-PACKETS'].append({
                                        'length': len(encrypted_payload),
                                        'ciphertext': encrypted_payload.hex()
                                    })
                                except:
                                    packets_transcript_json['HANDSHAKE-PACKETS'] = []
                                    packets_transcript_json['HANDSHAKE-PACKETS'].append({
                                        'length': len(encrypted_payload),
                                        'ciphertext': encrypted_payload.hex()
                                    })


    
        print("\n*****************************************************************************************************************************************************************************\n\n\n")

    prepare_parameters(packets_transcript_json) # capire come rimuovere HEADER Crypto dai pacchetti di handsahke
 
        # if 'tcp' in packet:
        #     stream_id=packet.tcp.stream
        #     if stream_id not in tcp_streams:
        #         print("(",stream_id,") New stream")
        #         tcp_streams[stream_id]=[]
        #         status[stream_id]=copy.deepcopy(tls_session)
        #     tcp_streams[stream_id].append(packet)
            
        #     if 'tls' in packet:
        #         #if hasattr(packet.tls, 'handshake') and not hasattr(packet.tls, 'handshake_session_id_length'): #???
        #         #    print(packet.tls)
        #         #    continue
        #         if hasattr(packet.tls, 'handshake') and int(packet.tls.handshake_session_id_length)>0:
        #             if packet.tls.handshake_type == '1': #Client Hello
        #                 print("(",stream_id,") Client Hello")
        #                 status[stream_id]['CH'] = True
        #                 status[stream_id]['src']=packet.tcp.srcport
        #                 status[stream_id]['dst']=packet.tcp.dstport
        #                 #print(status)
        #                 transcripts[stream_id]=copy.deepcopy(transcript)
        #                 Cx=toHex(packet.tls.handshake_extensions_key_share_key_exchange)[1:33]
        #                 transcripts[stream_id]["Cx"]=Cx
        #                 Cy=toHex(packet.tls.handshake_extensions_key_share_key_exchange)[33:65]
        #                 transcripts[stream_id]["Cy"]=Cy
        #                 ch_sh = parseApplicationData(toHex(packet.tcp.payload))[0][1]
                        
        #                 #print(packet.tls._all_fields)
        #                 #session_id = packet.tls.handshake_session_id
        #                 client_random = packet.tls.handshake_random
        #                 transcripts[stream_id]["RandomID"] = client_random
        #                 cipher_suites = packet.tls.handshake_ciphersuites
        #             elif packet.tls.handshake_type == '2':
        #                 print("(",stream_id,") Server Hello")
        #                 if status[stream_id] and status[stream_id]["CH"] and status[stream_id]["src"]==packet.tcp.dstport:
        #                     status[stream_id]["SH"]=True
        #                     status[stream_id]["src"]=packet.tcp.srcport
        #                     status[stream_id]["dst"]=packet.tcp.dstport
        #                     ch_sh+=parseApplicationData(toHex(packet.tcp.payload))[0][1]
        #                     transcripts[stream_id]["ch_sh"]=ch_sh
        #                     transcripts[stream_id]["ch_sh_len"]=len(ch_sh)
        #                     Sx=toHex(packet.tls.handshake_extensions_key_share_key_exchange)[1:33]
        #                     transcripts[stream_id]["Sx"]=Sx
        #                     Sy=toHex(packet.tls.handshake_extensions_key_share_key_exchange)[33:65]
        #                     transcripts[stream_id]["Sy"]=Sy
        #                     hasher=sha256()
        #                     hasher.update(ch_sh)
        #                     ch_sh_hash=hasher.digest()
        #                     transcripts[stream_id]["H2"]=ch_sh_hash
        #                 else: print("Errors")
        #         if hasattr(packet.tls, 'change_cipher_spec'):
        #             if status[stream_id] and packet.tcp.srcport==status[stream_id]["src"]:    #it's subsequent to a server hello, so it's from SERVER
        #                 print("(",stream_id,") Server ", end="")
        #                 if status[stream_id]["SH"]:
        #                     status[stream_id]["S_CS"]=True
        #                 else: print("Errors")

        #                 #raw_payload = bytearray.fromhex(packet.tcp.payload.replace(':','')) #saves the raw bytes of the entire tcp payload of the packet
        #                 #msgs = parseApplicationData(raw_payload)
        #                 '''for msg in msgs:
        #                     if msg[0]==23:
        #                         print("Found app data in SH")
        #                         app_data+=msg[1]'''
                        
        #             elif status[packet.tcp.stream] and packet.tcp.dstport==status[packet.tcp.stream]["src"]:         #it's subsequent to a server finished -> is from the CLIENT
        #                 print("(",stream_id,") Client ", end="")
        #                 if status[packet.tcp.stream]["SF"]:
        #                     status[packet.tcp.stream]["C_CS"]=True
        #                     status[packet.tcp.stream]["src"]=packet.tcp.srcport
        #                     status[packet.tcp.stream]["dst"]=packet.tcp.dstport
        #                 else: print("Errors at Client_ChangeCipherSpec")
        #             print("Change_CipherSpec")
        #             if hasattr(packet.tls, 'app_data'):
        #                 print("(",stream_id,") Application Data: ", end="")
        #                 app_data=elaborateAppData(packet,stream_id)

                
        #         elif not hasattr(packet.tls, 'handshake'):
        #             #print("Not a handshake")
        #             #if(append) and moreDataCondition(packet):     #uncomment if appendMoreData is fixed and if necessary to manually rebuild tls
        #             #    buffer = appendMoreData(packet, buffer)

        #             #TODO: check this condition: Could be that SF is not contained in app_data?
                    
        #             if (hasattr(packet.tls, 'app_data') 
        #                  and status[stream_id]["src"]==packet.tcp.srcport): #if two from same direction: it's next to change_ciphertext or another app_data
        #                 print("(",stream_id,") Application Data: ", end="")
                        
        #                 if status[packet.tcp.stream]["S_CS"] and not status[packet.tcp.stream]["SF"]: #it's still handshake
        #                     print("Shouldnt enter here")
        #                     if status[packet.tcp.stream]["App"]:
        #                         print("Implement: merge all appData packets; pyshark cannot separate the 4 record layers autonomosuly, extract tcp.payload")
                            
        #                     else:
        #                         print("Server Finished")
        #                         handshake_ct=toHex(packet.tls.app_data)
        #                         #assume SF is inside the big packet
        #                         status[packet.tcp.stream]["SF"] = True
        #                         status[packet.tcp.stream]["src"]=packet.tcp.srcport
        #                         status[packet.tcp.stream]["dst"]=packet.tcp.dstport
        #                         #handshake_ct=handshake_ct[:-17]
        #                         transcripts[stream_id]['ServExt_ct']=handshake_ct
        #                         transcripts[stream_id]['ServExt_ct_len']=len(handshake_ct)
        #                         transcripts[stream_id]['ServExt_ct_tail']=getTail(handshake_ct, ch_sh)
        #                 elif status[packet.tcp.stream]["C_CS"] and not status[packet.tcp.stream]["CF"]: #it's still handshake
        #                     print("Shouldnt enter here 2")
        #                     status[packet.tcp.stream]["CF"]=True 
        #                     status[packet.tcp.stream]["src"]=packet.tcp.srcport
        #                     status[packet.tcp.stream]["dst"]=packet.tcp.dstport
        #                     print(status)
        #                 elif status[packet.tcp.stream]["CF"] and status[packet.tcp.stream]["src"]==packet.tcp.srcport: #app data after CF-> the request
        #                     print("App Layer Request")
        #                     #print(packet.tls.app_data)
        #                     status[stream_id]['App']+=1
        #                     print(status[stream_id])
        #                     transcripts[stream_id]['appl_ct']=toHex(packet.tls.app_data)[:-17] #Check: odd byte number
        #                     transcripts[stream_id]['PacketNumber'] = status[stream_id]['App']
        #                     name = print_transcript(transcripts[stream_id], stream_id)
        #                     print("Computing inputs")
                            
        #                     #java_call = threading.Thread(target=call_java, args=(name,))
        #                     #threads.append(java_call)
        #                     #java_call.start()
                            
        #                     #TODO: consider implementing a queue for incoming new processes

        #             #print(status)
        #             #print(buffer.hex(),'\n')
        #             #print(packet.tls.record_length, packet.tls.app_data)

        #     #handle TCP streams to make sure the flow is consistent
        #     elif packet.tcp.stream in status and int(packet.tcp.len)>0: 
                    
        #             print("(",stream_id,") Not TLS")
        #             '''if moreDataCondition(packet):
        #                 if append:
                            
        #                     buffer = appendMoreData(packet, buffer)
        #                 else:
                            
        #                     buffer = toHex(packet.tcp.payload)
        #                     #print(packet.tcp)
        #             elif not moreDataCondition(packet) and len(buffer)>0:
        #                 #print(buffer.hex())
        #                 print("Finished buffering")
        #                 #print(buffer)
        #                 msgs=parseApplicationData(buffer)
        #                 print('\n')
        #                 buffer=bytearray()'''

    #printTranscript(transcripts)
    #for line in runProcess("java -cp xjsnark_decompiled/backend_bin_mod/:xjsnark_decompiled/xjsnark_bin/ xjsnark.channel_openings.ChannelShortcut pub".split()):
    #    print(line)


import threading
from runprocess import runProcess

print("STARTING CAPTURE . . .\n\n")
pcap_file = "quic_exchange.pcap" # when capturing remember to BPF filter by destination ip and port!
capturer = threading.Thread(target=process_with_pyshark, args=(pcap_file,))
threads.append(capturer)
capturer.start()