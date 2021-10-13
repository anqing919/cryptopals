from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits,randrange

def AES_encrypt_orcale(pt):
    pt = get_random_bytes(randrange(5,10)) + pt + get_random_bytes(randrange(5,10))
    key = get_random_bytes(AES.block_size)
    if getrandbits(1) == 0:
        return "ECB",AES.new(key,AES.MODE_ECB).encrypt(pad(pt,AES.block_size))
    else:
        return "CBC",AES.new(key,AES.MODE_CBC,get_random_bytes(AES.block_size)).encrypt(pad(pt,AES.block_size))

def detect_encrypt(ct):
    ct_chunks = [ct[i:i+AES.block_size] for i in range(0,len(ct),AES.block_size)]
    repetition = len(ct_chunks) - len(set(ct_chunks))
    if repetition > 0:
        return "ECB"
    else:
        return "CBC"

if __name__ == "__main__":
    sum_count = 100
    test_pt = [
        bytes([0]*32),
        bytes([0]*64),
        get_random_bytes(AES.block_size * 4),
    ]
    # The result below shows that only if the plaintext is disciplinarian and long enough
    # can we detect the mode of encryption.
    # We should recongize that we act as advesary here, which means we can send anything to
    # the chal. to detect which the mode of encryption is using.
    for i,pt in enumerate(test_pt): 
        right_count = 0
        for _ in range(sum_count):
            encrypt_type, ct = AES_encrypt_orcale(pt)
            detect_type = detect_encrypt(ct)
            if encrypt_type == detect_type:
                right_count += 1
        print("[Test {}] PT = {}\nRight rate = {}".format(i,pt,right_count/sum_count))
