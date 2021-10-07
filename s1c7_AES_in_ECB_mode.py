import binascii
import sys
from Crypto.Cipher import AES

def AEC_ECB_decrypto(ct,key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ct)

if __name__ == "__main__":
    with open(sys.path[0]+"/s1c7_ct.txt") as cipherfile:
        ct = binascii.a2b_base64(cipherfile.read())
    key = b"YELLOW SUBMARINE"
    ct = AEC_ECB_decrypto(ct,key)
    print(ct.decode())