import sys
from s1c3_single_byte_xor_cipher import burteforce_single_char_xor

def detect_single_char_xor(ct_list):
    candidate = []
    for line in ct_list:
        candidate.append(burteforce_single_char_xor(line))
    # Run the print below, and we recognize that only one line is English.
    # print(candidate)
    return sorted(candidate, key=lambda x:x["score"], reverse=True)[0]

if __name__ == "__main__":
    ct_list = [bytes.fromhex(line.strip()) for line in open(sys.path[0]+"/s1c4_ct.txt")]
    print(detect_single_char_xor(ct_list)["pt"].decode().strip())