import sys 
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

if __name__ == "__main__":
    with open(sys.path[0]+"/s2c10_ct.txt") as cipherfile:
        ct = binascii.a2b_base64(cipherfile.read())
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * AES.block_size
    cipher = AES.new(key,AES.MODE_CBC,iv)
    pt = unpad(cipher.decrypt(ct),AES.block_size)
    print(pt.decode())
