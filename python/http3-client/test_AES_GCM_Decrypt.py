from Crypto.Cipher import AES
import binascii

key = binascii.unhexlify('9189d5c27ded9afb998cd77a4f378ed0')
data = binascii.unhexlify('9c998ea68770f16ae5a3f37cf492b6b7b9498f3a5a95fb21da4775bc01c812b028b2e59b0d2f953721d87eae001fede270964a8d477108633a430cca3cef')
nonce = binascii.unhexlify('879a6ded788e315efe23103c')
cipher = AES.new(key, AES.MODE_GCM, nonce)
dec = cipher.decrypt(data)
print(dec.hex())

# 100 Bytes = 84 Bytes + 16 Bytes (Tag)
# 84 Bytes / 16 bytes = 6 blocks (blocks_number)
# 38 bytes (prima di quello che voglio cifrare, head) / 16 bytes = 2 blocks (head_block_number)
# Parto dal blocco 2 con offset = 38 % 16 = 6 bytes
# 6 blocks  (gcm_block_number)