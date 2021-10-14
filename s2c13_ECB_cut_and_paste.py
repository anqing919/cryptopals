from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# New? Read:https://braincoke.fr/write-up/cryptopals/cryptopals-ecb-cut-and-paste/

class ECB_Orcale:
    uid = 9

    def __init__(self) -> None:
        self.__key = get_random_bytes(AES.key_size[0])
        self.__cipher = AES.new(self.__key, AES.MODE_ECB)

    def encrypt(self, email):
        kv_encoded = self.kv_encode(self.profile_for(email)).encode()
        return self.__cipher.encrypt(pad(kv_encoded, AES.block_size))

    def decrypt(self,ct):
        return unpad(self.__cipher.decrypt(ct), AES.block_size)

    def profile_for(self, email):
        email = email.replace('&','').replace('=','')
        self.uid += 1
        return {
            "email": email,
            "uid": str(self.uid),
            "role": "user"
        }
    def kv_encode(self, dict_date):
        kv_encoded = ''
        for item in dict_date.items():
            kv_encoded += item[0] + '=' + item[1] + '&'
        return kv_encoded[:-1]

    def kv_parse(self, kv_encoded):
        dict_date = {}
        kvs = kv_encoded.split('&')
        for kv in kvs:
            parts = kv.split('=')
            dict_date[parts[0]] = parts[1]
        return dict_date

def cut_and_paste(oracle):
    prefix_len = AES.block_size - len("email=")
    suffix_len = AES.block_size - len("admin")
    email1 = 'A' * prefix_len + "admin" + chr(suffix_len) * suffix_len
    ct1 = oracle.encrypt(email1)

    pad_len = 2 * AES.block_size - len("email=") - len("&uid=10&role=")
    email2 = 'A' * pad_len
    ct2 = oracle.encrypt(email2)
    return ct2[:32] + ct1[16:32]

if __name__ == "__main__":
    orcale = ECB_Orcale()
    trick = cut_and_paste(orcale)
    info = orcale.decrypt(trick)
    print("info:",info)
    role = orcale.kv_parse(info.decode())["role"]
    print(role)
