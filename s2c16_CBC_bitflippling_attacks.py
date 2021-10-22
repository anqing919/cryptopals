from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from s2c14_byte_at_a_time_ECB_decryption_harder import find_block_len,find_prefix_len

class CBC_Oracle:
    def __init__(self) -> None:
        self.__key = get_random_bytes(AES.key_size[0])
        self.__iv = get_random_bytes(AES.block_size)
        self.__prefix = "comment1=cooking%20MCs;userdata="
        self.__suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
        # self.__cipher = AES.new(self.__key, AES.MODE_CBC, self.__key)

    def encrypt(self, message):
        # Without adding iv at the head of cipher text.
        message = message.replace(';','').replace('=','')
        total_pt = self.__prefix + message + self.__suffix
        cipher = AES.new(self.__key, AES.MODE_CBC, self.__iv)
        return cipher.encrypt(pad(total_pt.encode(), AES.block_size))
    
    def decrypt_and_verify(self, ct):
        # Verify whether the cipher text contains ";admin=true;"
        cipher = AES.new(self.__key, AES.MODE_CBC, self.__iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("PT =",pt)
        # return pt.contains(";admin=true;")
        return b";admin=true;" in pt

def find_block_len(oracle_encrypt):
    work = ''
    init_len = len(oracle_encrypt(work))
    new_len = init_len
    while new_len == init_len:
        work += 'A'
        new_len = len(oracle_encrypt(work))
    return new_len - init_len

def find_prefix_len(oracle_encrypt, block_len):
    encrypt_A = oracle_encrypt('A')
    encrypt_B = oracle_encrypt('B')
    for i in range(0, len(encrypt_A), block_len):
        if encrypt_A[i:i+block_len] != encrypt_B[i:i+block_len]:
            chunk_len = i
            break
    for i in range(1, block_len + 1):
        encrypt_A = oracle_encrypt(i*'x' + 'A')
        encrypt_B = oracle_encrypt(i*'x' + 'B')
        if encrypt_A[chunk_len:chunk_len+block_len] == encrypt_B[chunk_len:chunk_len+block_len]:
            bits_left_len = block_len - i
    return chunk_len + bits_left_len

def bitflippling_attacks(oracle):
    # block_len = find_block_len(oracle.encrypt())
    block_len = find_block_len(oracle.encrypt)
    prefix_len = find_prefix_len(oracle.encrypt, block_len)
    prefix_add_len = (block_len - prefix_len) % block_len

    pt = "?admin?true?"
    pt_add_len = (block_len - len(pt)) % block_len

    true_ct = oracle.encrypt(prefix_add_len*'?' + pt_add_len*'?' + pt)
    # total_len = prefix_len + prefix_add_len +  pt_add_len + len(pt)
    # print(total_len)
    # fake_ct =  true_ct[:total_len-12] + bytes([true_ct[total_len-12] ^ ord('?')^ord(';')]) + \
    #            true_ct[total_len-11:total_len-6] + bytes([true_ct[total_len-6]^ord('?')^ord('=')]) + \
    #            true_ct[total_len-5:total_len-1] + bytes([true_ct[total_len-1]^ord('?')^ord(';')]) +\
    #            true_ct[total_len:]
    total_len = prefix_len + prefix_add_len 
    fake_ct =  true_ct[:total_len-12] + bytes([true_ct[total_len-12] ^ ord('?')^ord(';')]) + \
               true_ct[total_len-11:total_len-6] + bytes([true_ct[total_len-6]^ord('?')^ord('=')]) + \
               true_ct[total_len-5:total_len-1] + bytes([true_ct[total_len-1]^ord('?')^ord(';')]) +\
               true_ct[total_len:]
    # print("len(true)={} len(fake)={}".format(len(true_ct),len(fake_ct)))
    return oracle.decrypt_and_verify(fake_ct)

if __name__ == "__main__":
    oracle = CBC_Oracle()
    print(bitflippling_attacks(oracle))
