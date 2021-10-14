import binascii
import itertools
import sys
from s1c3_single_byte_xor_cipher import bruteforce_single_char_xor
from s1c5_implement_repeat_key_xor import key_xor

def hamming_dist(a,b):
    assert len(a) == len(b)
    return sum([bin(x^y).count('1') for (x,y) in zip(a,b)])
    
def find_keylen(ct):
    keylen_candidate = []
    for keylen in range(2,41):    
        sum_hamming = 0
        seg = []
        for i in range(4):
            seg.append(ct[keylen*i:keylen*(i+1)])
        for (i,j) in itertools.combinations(seg,2):
            sum_hamming += hamming_dist(i,j)
        nor_avg_hamm = sum_hamming/(6*keylen)
        data = {"keylen":keylen,"hamm":nor_avg_hamm}
        keylen_candidate.append(data)
    return sorted(keylen_candidate, key=lambda x:x["hamm"], reverse=False)[:3] 

def bruteforce_key_xor(ct, keylen):
    key = []
    # 分块
    for index in range(keylen):
        block_ct = ct[index::keylen]
        key.append(bruteforce_single_char_xor(block_ct)["key"])
    return bytes(key)

if __name__ == "__main__":
    assert(hamming_dist(b"this is a test",b"wokka wokka!!!") == 37)
    with open(sys.path[0]+"/s1c6_ct.txt") as cipherfile:
        ct = binascii.a2b_base64(cipherfile.read())
    keylen_candidate = [x["keylen"] for x in find_keylen(ct)]
    for keylen in keylen_candidate:
        key = bruteforce_key_xor(ct, keylen)
        pt = key_xor(ct,key)
        print("KEY = ",key)
        print("PT = ",pt.decode())
        print("===============================")     