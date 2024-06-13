from Crypto.Cipher import AES
import binascii

key = binascii.unhexlify('efe7e0774c7cae2651d33c7eb26c9af1')
data = binascii.unhexlify('300e818698198db8623097e62a5ef95d 47b5d953d1029caea12978de2b4696b8 2276065c513dfbf492e59d1cc31e2195 4851f0b099573eb7c94467cc640e6c4229ef4fb3b95369354c0bfad2e1b05feb8f13afdf')
nonce = binascii.unhexlify('41ba9c7a80f4beb174f83be7')
cipher = AES.new(key, AES.MODE_GCM, nonce)
dec = cipher.decrypt(data)
print(dec.hex())

# 100 Bytes = 84 Bytes + 16 Bytes (Tag)
# 84 Bytes / 16 bytes = 6 blocks (blocks_number)
# 38 bytes (prima di quello che voglio cifrare, head) / 16 bytes = 2 blocks (head_block_number)
# Parto dal blocco 2 con offset = 38 % 16 = 6 bytes
# 6 blocks  (gcm_block_number)