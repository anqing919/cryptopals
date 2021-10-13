import sys
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

def bytes_xor(a,b):
    assert(len(a) == len(b))
    return bytes(x^y for (x,y) in zip(a,b))

def AES_CBC_encrypt(pt,key,iv):
    pt = pad(pt,AES.block_size)
    pt_list = [pt[i:i+AES.block_size] for i in range(0,len(pt),AES.block_size)]
    ct = iv
    # The ECB mode does not need iv, so do not pass it as a paramter.
    cipher = AES.new(key, AES.MODE_ECB)  
    tmp = iv
    for i in range(len(pt_list)):
        tmp = cipher.encrypt(bytes_xor(tmp,pt_list[i]))
        ct += tmp
    return ct

def AES_CBC_decrypt(ct, key):
    pt = b""
    ct_list = [ct[i:i+AES.block_size] for i in range(0,len(ct),AES.block_size)]
    cipher = AES.new(key,AES.MODE_ECB)
    for i in range(1,len(ct_list)):
        pt += bytes_xor(ct_list[i-1],cipher.decrypt(ct_list[i]))
    return unpad(pt,AES.block_size)

def AES_CBC_decrypt_withIV(ct, key, iv):
    pt = b""
    ct_list = [ct[i:i+AES.block_size] for i in range(0,len(ct),AES.block_size)]
    ct_list.insert(0,iv)
    cipher = AES.new(key,AES.MODE_ECB)
    for i in range(1,len(ct_list)):
        pt += bytes_xor(ct_list[i-1],cipher.decrypt(ct_list[i]))
    return unpad(pt,AES.block_size)

if __name__ == "__main__":
    with open(sys.path[0]+"/s2c10_ct.txt") as cipherfile:
        ct = binascii.a2b_base64(cipherfile.read())
    key = b"YELLOW SUBMARINE" 
    pt1 = AES_CBC_decrypt(ct,key)
    # We will see that the first part of the cipher text is not the IV.
    print(pt1.decode())

    iv = b"\x00" * AES.block_size
    pt2 = AES_CBC_decrypt_withIV(ct,key,iv)
    print(pt2.decode())

    ct3 = b"Hello World!\nJKA"
    key3 = b"\x11" * AES.block_size
    iv3 = b"\x00" * AES.block_size
    print(AES_CBC_decrypt(AES_CBC_encrypt(ct3,key3,iv3),key3))

    