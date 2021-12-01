import binascii
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random.random import choice
from Crypto.Random import get_random_bytes

class CBC_oracle:
    def __init__(self) -> None:
        self.__key = get_random_bytes(AES.key_size[0])
        self.__iv = get_random_bytes(AES.block_size)
        self.__choice = choice([
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
        ])

    def encrypt(self):
        cipher = AES.new(self.__key, AES.MODE_CBC, self.__iv)
        return cipher.encrypt(pad(binascii.a2b_base64(self.__choice), AES.block_size))

    def detect_padding(self, ct):
        cipher = AES.new(self.__key, AES.MODE_CBC, self.__iv)
        print("len(ct):",len(ct))
        pt = cipher.decrypt(ct)
        padding = pt[-pt[-1]:]
        return all(i == pt[-1] for i in padding)

# # TypeError: 'bytes' object does not support item assignment
# # （比特）字符串是不可变的
def cbc_padding_oracle(oracle_decrypt, ct):
    ct_list = [ct[i:i+AES.block_size] for i in range(0, len(ct), AES.block_size)]
    pt = ""
    for chunk_pos in range(len(ct_list) - 1):
        iv_work = [0] * AES.block_size
        median_work = [0] * AES.block_size
        for iv_byte_pos in range(AES.block_size - 1, -1, -1):
            iv_work[iv_byte_pos+1:] = [(AES.block_size - iv_byte_pos) ^ x for x in median_work[iv_byte_pos+1:]]
            for iv_byte_value in range(0x100):
                iv_work[iv_byte_pos] = iv_byte_value
                # ct_work = "".join(iv_work + list(ct_list[chunk_pos+1]))
                ct_work = "".join([chr(i) for i in (iv_work + list(ct_list[chunk_pos + 1]))])
                print(len(ct_work))
                print(len(ct_work.encode()))
                padding_right = oracle_decrypt(ct_work.encode())
                if padding_right == 1:
                    break
            median_work[iv_byte_pos] = (AES.block_size - iv_byte_pos) ^ iv_byte_value
        pt += "".join([chr(x^y) for (x,y) in zip(ct_list[chunk_pos], median_work)])
    return pt

if __name__ == "__main__":
    oracle = CBC_oracle()
    ct = oracle.encrypt()
    pt = cbc_padding_oracle(oracle.detect_padding, ct)
    print("PT =", pt.strip())