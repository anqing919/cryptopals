
# import binascii
# print("hello")
# base1 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
# print(len(binascii.a2b_base64(base1).decode()))
# print(binascii.a2b_base64(base1))

# from Crypto.Cipher import AES

# key = b'Sixteen byte key'
# data = b'hello from other side'
# cipher = AES.new(key, AES.MODE_EAX)

# e_data = cipher.encrypt(data)
# d_data = cipher.decrypt(e_data)

# print("Encryption was: ", e_data)
# print("Original Message was: ", d_data)


str1 = "12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4"
for i,x in enumerate(str1):
    print(i+1,x)