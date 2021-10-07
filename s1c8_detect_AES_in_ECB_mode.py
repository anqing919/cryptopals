import binascii
from os import path
import sys
from Crypto.Cipher import AES

def detect_AES_ECB(ct_list):
    candidate = [{"pos":-1,"rep":0}]
    for (pos,ct) in enumerate(ct_list):
        # Calculate the num of repetitions of each line.
        chunk = [ct[i:i+AES.block_size] for i in range(0,len(ct),AES.block_size)]
        repetition = len(chunk) - len(set(chunk))
        data = {"pos":pos, "rep":repetition}
        candidate.append(data)
    # The question doesn't ask us to bruteforcely calculate the plaintext.
    return sorted(candidate, key=lambda x:x["rep"], reverse=True)[0]

if __name__ == "__main__":
    ct_list = [binascii.a2b_hex(line.strip()) for line in open(sys.path[0]+"/s1c8_ct.txt")]
    # Without strip(), it will work wrong, why?
    # ct_list = [binascii.a2b_hex(line.strip()) for line in open(sys.path[0]+"/s1c8_ct.txt")]
    result = detect_AES_ECB(ct_list)
    print("The ciphertext encrypted in ECB mode is at position {} which contains {} repetitions.".format(result["pos"],result["rep"]))
