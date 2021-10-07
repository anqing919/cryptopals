import binascii
import sys

from s1c5_implement_repeat_key_xor import key_xor

print(binascii.a2b_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
print(binascii.unhexlify("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
print(bytes.fromhex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
print((binascii.a2b_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")).decode())

# with open("s1c4_ct.txt") as cf:
#     print(cf)
#     for i in cf:
#         print(len(binascii.a2b_hex(i.strip())))

# with open("s1c4_ct.txt") as cf:
#     print(cf)
#     for line in cf.readlines():
#         print(len(bytes.fromhex(line.strip())))

print(sys.path[0])

with open("s1c6_ct.txt") as cf:
    ct = binascii.a2b_base64(cf.read())
print(binascii.b2a_qp(key_xor(ct,b'\x00\x00')))