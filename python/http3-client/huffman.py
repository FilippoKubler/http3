"""
HPACK Huffman Coding Table (GOOGLE) - https://www.rfc-editor.org/rfc/rfc7541.html#appendix-B
Used in QPACK too
"""
huffman_encoding_table = {
    ' ':    '010100',
    '!':    '1111111000',
    '"':    '1111111001',
    '#':    '111111111010',
    '$':    '1111111111001',
    '%':    '010101',
    '&':    '11111000',
    '\'':   '11111111010',
    '(':    '1111111010',
    ')':    '1111111011',
    '*':    '11111001',
    '+':    '11111111011',
    ',':    '11111010',
    '-':    '010110',
    '.':    '010111',
    '/':    '011000',
    '0':    '00000',
    '1':    '00001',
    '2':    '00010',
    '3':    '011001',
    '4':    '011010',
    '5':    '011011',
    '6':    '011100',
    '7':    '011101',
    '8':    '011110',
    '9':    '011111',
    ':':    '1011100',
    ';':    '11111011',
    '<':    '111111111111100',
    '=':    '100000',
    '>':    '111111111011',
    '?':    '1111111100',
    '@':    '1111111111010',
    'A':    '100001',
    'B':    '1011101',
    'C':    '1011110',
    'D':    '1011111',
    'E':    '1100000',
    'F':    '1100001',
    'G':    '1100010',
    'H':    '1100011',
    'I':    '1100100',
    'J':    '1100101',
    'K':    '1100110',
    'L':    '1100111',
    'M':    '1101000',
    'N':    '1101001',
    'O':    '1101010',
    'P':    '1101011',
    'Q':    '1101100',
    'R':    '1101101',
    'S':    '1101110',
    'T':    '1101111',
    'U':    '1110000',
    'V':    '1110001',
    'W':    '1110010',
    'X':    '11111100',
    'Y':    '1110011',
    'Z':    '11111101',
    '[':    '1111111111011',
    '\\':   '1111111111111110000',
    ']':    '1111111111100',
    '^':    '11111111111100',
    '_':    '100010',
    '`':    '111111111111101',
    'a':    '00011',
    'b':    '100011',
    'c':    '00100',
    'd':    '100100',
    'e':    '00101',
    'f':    '100101',
    'g':    '100110',
    'h':    '100111',
    'i':    '00110',
    'j':    '1110100',
    'k':    '1110101',
    'l':    '101000',
    'm':    '101001',
    'n':    '101010',
    'o':    '00111',
    'p':    '101011',
    'q':    '1110110',
    'r':    '101100',
    's':    '01000',
    't':    '01001',
    'u':    '101101',
    'v':    '1110111',
    'w':    '1111000',
    'x':    '1111001',
    'y':    '1111010',
    'z':    '1111011',
    '{':    '111111111111110',
    '|':    '11111111100',
    '}':    '11111111111101',
    '~':    '1111111111101',
}

huffman_decoding_table = {
    '010100':               ' ',
    '1111111000':           '!',
    '1111111001':           '"',
    '111111111010':         '#',
    '1111111111001':        '$',
    '010101':               '%',
    '11111000':             '&',
    '11111111010':          '\'',
    '1111111010':           '(',
    '1111111011':           ')',
    '11111001':             '*',
    '11111111011':          '+',
    '11111010':             ',',
    '010110':               '-',
    '010111':               '.',
    '011000':               '/',
    '00000':                '0',
    '00001':                '1',
    '00010':                '2',
    '011001':               '3',
    '011010':               '4',
    '011011':               '5',
    '011100':               '6',
    '011101':               '7',
    '011110':               '8',
    '011111':               '9',
    '1011100':              ':',
    '11111011':             ';',
    '111111111111100':      '<',
    '100000':               '=',
    '111111111011':         '>',
    '1111111100':           '?',
    '1111111111010':        '@',
    '100001':               'A',
    '1011101':              'B',
    '1011110':              'C',
    '1011111':              'D',
    '1100000':              'E',
    '1100001':              'F',
    '1100010':              'G',
    '1100011':              'H',
    '1100100':              'I',
    '1100101':              'J',
    '1100110':              'K',
    '1100111':              'L',
    '1101000':              'M',
    '1101001':              'N',
    '1101010':              'O',
    '1101011':              'P',
    '1101100':              'Q',
    '1101101':              'R',
    '1101110':              'S',
    '1101111':              'T',
    '1110000':              'U',
    '1110001':              'V',
    '1110010':              'W',
    '11111100':             'X',
    '1110011':              'Y',
    '11111101':             'Z',
    '1111111111011':        '[',
    '1111111111111110000':  '\\',
    '1111111111100':        ']',
    '11111111111100':       '^',
    '100010':               '_',
    '111111111111101':      '`',
    '00011':                'a',
    '100011':               'b',
    '00100':                'c',
    '100100':               'd',
    '00101':                'e',
    '100101':               'f',
    '100110':               'g',
    '100111':               'h',
    '00110':                'i',
    '1110100':              'j',
    '1110101':              'k',
    '101000':               'l',
    '101001':               'm',
    '101010':               'n',
    '00111':                'o',
    '101011':               'p',
    '1110110':              'q',
    '101100':               'r',
    '01000':                's',
    '01001':                't',
    '101101':               'u',
    '1110111':              'v',
    '1111000':              'w',
    '1111001':              'x',
    '1111010':              'y',
    '1111011':              'z',
    '111111111111110':      '{',
    '11111111100':          '|',
    '11111111111101':       '}',
    '1111111111101':        '~',
}


huffman_static_table = {
    '0':	':authority',
    '1':    ':path = /',
    '2':    'age = 0',
    '3':    'content-disposition',
    '4':    'content-length = 0',
    '5':    'cookie',
    '6':    'date',
    '7':    'etag',
    '8':    'if-modified-since',
    '9':    'if-none-match',
    '10': 	'last-modified',
    '11': 	'link',
    '12': 	'location',
    '13': 	'referer',
    '14': 	'set-cookie',
    '15': 	':method = CONNECT',
    '16': 	':method = DELETE',
    '17': 	':method = GET',
    '18': 	':method = HEAD',
    '19': 	':method = OPTIONS',
    '20': 	':method = POST',
    '21': 	':method = PUT',
    '22': 	':scheme = http',
    '23': 	':scheme = https',
    '24': 	':status = 103',
    '25': 	':status = 200',
    '26': 	':status = 304',
    '27': 	':status = 404',
    '28': 	':status = 503',
    '29': 	'accept = */*',
    '30': 	'accept = application/dns-message',
    '31': 	'accept-encoding = gzip, deflate, br',
    '32': 	'accept-ranges = bytes',
    '33': 	'access-control-allow-headers = cache-control',
    '34': 	'access-control-allow-headers = content-type',
    '35': 	'access-control-allow-origin = *',
    '36': 	'cache-control = max-age=0',
    '37': 	'cache-control = max-age=2592000',
    '38': 	'cache-control = max-age=604800',
    '39': 	'cache-control = no-cache',
    '40': 	'cache-control = no-store',
    '41': 	'cache-control = public, max-age=31536000',
    '42': 	'content-encoding = br',
    '43': 	'content-encoding = gzip',
    '44': 	'content-type = application/dns-message',
    '45': 	'content-type = application/javascript',
    '46': 	'content-type = application/json',
    '47': 	'content-type = application/x-www-form-urlencoded',
    '48': 	'content-type = image/gif',
    '49': 	'content-type = image/jpeg',
    '50': 	'content-type = image/png',
    '51': 	'content-type = text/css',
    '52': 	'content-type = text/html; charset=utf-8',
    '53': 	'content-type = text/plain',
    '54': 	'content-type = text/plain;charset=utf-8',
    '55': 	'range = bytes=0-',
    '56': 	'strict-transport-security = max-age=31536000',
    '57': 	'strict-transport-security = max-age=31536000; includesubdomains',
    '58': 	'strict-transport-security = max-age=31536000; includesubdomains; preload',
    '59': 	'vary = accept-encoding',
    '60': 	'vary = origin',
    '61': 	'x-content-type-options = nosniff',
    '62': 	'x-xss-protection = 1; mode=block',
    '63': 	':status = 100',
    '64': 	':status = 204',
    '65': 	':status = 206',
    '66': 	':status = 302',
    '67': 	':status = 400',
    '68': 	':status = 403',
    '69': 	':status = 421',
    '70': 	':status = 425',
    '71': 	':status = 500',
    '72': 	'accept-language = ',
    '73': 	'access-control-allow-credentials = FALSE',
    '74': 	'access-control-allow-credentials = TRUE',
    '75': 	'access-control-allow-headers = *',
    '76': 	'access-control-allow-methods = get',
    '77': 	'access-control-allow-methods = get, post, options',
    '78': 	'access-control-allow-methods = options',
    '79': 	'access-control-expose-headers = content-length',
    '80': 	'access-control-request-headers = content-type',
    '81': 	'access-control-request-method = get',
    '82': 	'access-control-request-method = post',
    '83': 	'alt-svc = clear',
    '84': 	'authorization',
    '85': 	'content-security-policy = script-src \'none\'; object-src \'none\'; base-uri \'none\'',
    '86': 	'early-data = 1',
    '87': 	'expect-ct',
    '88': 	'forwarded',
    '89': 	'if-range',
    '90': 	'origin',
    '91': 	'purpose = prefetch',
    '92': 	'server',
    '93': 	'timing-allow-origin = *',
    '94': 	'upgrade-insecure-requests = 1',
    '95': 	'user-agent',
    '96': 	'x-forwarded-for',
    '97': 	'x-frame-options = deny',
    '98': 	'x-frame-options = sameorigin',
}



def round_up(x):
    return ((x + 7) & (-8))



def huffman_encoding(path: str):
    huffman_path_coding = ''
    for char in path:
        huffman_path_coding += huffman_encoding_table[char]

    return hex(int(huffman_path_coding.ljust(round_up(len(huffman_path_coding)), '1'), 2))[2:], round_up(round_up(len(huffman_path_coding)) - len(huffman_path_coding))



def huffman_decoding(headers):
    headers_binary = ''.join(format(byte, '08b') for byte in bytes.fromhex(headers))
    decoded_headers = ''
    # print(headers_binary, '\n\n')

    char = ''
    bits_to_skip = 0

    for i, c in enumerate(headers_binary):

        if bits_to_skip > 0:
            bits_to_skip -= 1
            continue
        
        char += c

        match (char):
            case '11': # Static Table  | RFC 9204 QPACK 4.5.2
                index = str(int(headers_binary[1+i:7+i], 2))
                decoded_header = huffman_static_table[index]
                # print(char + headers_binary[1+i:7+i])
                # print(decoded_header, '\n')
                decoded_headers += decoded_header + '\n'
                bits_to_skip = 6
                char = ''

            case '0101': # Static Table | RFC 9204 QPACK 4.5.4
                index = int(headers_binary[1+i:5+i], 2)

                j = 0
                if index == 15:
                    while True:
                        index += int(headers_binary[6+i+j:13+i+j], 2)
                        if headers_binary[5+i+j] == '0':
                            break
                        j += 8

                    j += 8

                decoded_header = huffman_static_table[str(index)]

                huffman = True if headers_binary[5+i+j] == '1' else False

                length = int(headers_binary[6+i+j:13+i+j], 2) * 8
                
                value = headers_binary[13+i+j:13+length+i+j]

                character = ''
                decoded_value = ''

                if huffman:

                    for bit in value:
                        character += bit

                        try:
                            decoded_value += huffman_decoding_table[character]
                            character = ''
                        except KeyError:
                            continue

                else:

                    for j in range(0, len(value), 8):
                        decoded_value += chr(int(value[j:j+8], 2))

                # print(char + headers_binary[1+i:5+i] + headers_binary[5+i:13+i+j] + value)

                if '=' in decoded_header:
                    index_of_symbol = decoded_header.index('=')
                    decoded_header = decoded_header[:index_of_symbol-1]
                decoded_header += ' ='
                # print(decoded_header, decoded_value, '\n')
                decoded_headers += decoded_header + ' ' + decoded_value + '\n'
                bits_to_skip = 12 + length + j
                char = ''
                decoded_value = ''

    print(decoded_headers)

"""
:method: POST   = 11010100 | 4.5.2 Static Table index 20
:scheme: https  = 11010111 | 4.5.2 Static Table index 23
:authority: 192.168.1.126:4433 = 01010000 10001101 00001011 11100010 01011100 00101110 00111100 10111000 01010111 00001000 10011100 10111000 11010011 01001100 10110011 | 4.5.4 Static Table index 0 (huffman - 13 bytes)
:path: /function/figlet = 01010001 10001100 01100010 01011011 01101010 00100010 01001100 01111010 10011000 10010100 11010011 01010000 01010100 11111111 | 4.5.4 Static Table index 1 (huffman - 12 bytes)
user-agent: aioquic/1.0.0 = 01011111 01010000 10001001 00011001 10001111 11011010 11010011 00010001 10000000 10101110 00000101 11000001 | 4.5.2 Static Table index 95
content-lenght: 9 = 01010100 00000001 00111001 | 4.5.4 Static Table index 4 (bytes - 1 byte)
content-type: application/x-www-form-urlencoded = 11101111 | 4.5.2 Static Table index 47
"""


"""
d4
11010100

d7
11010111

50 8d 0b e2 5c 2e 3c b8 57 08 9c b8 d3 4c b3 
01010000 10001101 00001011 11100010 01011100 00101110 00111100 10111000 01010111 00001000 10011100 10111000 11010011 01001100 10110011

51 8c 62 5b 6a 22 4c 7a 98 94 d3 50 54 ff
01010001 10001100 01100010 01011011 01101010 00100010 01001100 01111010 10011000 10010100 11010011 01010000 01010100 11111111

5f 50 89 19 8f da d3 11 80 ae 05 c1
01011111 01010000 10001001 00011001 10001111 11011010 11010011 00010001 10000000 10101110 00000101 11000001

54 01 39
01010100 00000001 00111001

ef
11101111
"""

# huffman_encoding('POST')

# input()

# First test: d4d7508d0be25c2e3cb857089cb8d34cb3518c625b6a224c7a9894d35054ff5f5089198fdad31180ae05c1540139ef
# Second test: 0000d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff5f5089198fdad31180ae05c1540134ef
huffman_decoding('d4d7508a089d5c0b8170dc69a659518c625b6a224c7a9894d35054ff')