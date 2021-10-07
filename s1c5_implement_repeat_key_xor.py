import binascii

def key_xor(m,k):
    len_k = len(k)
    return bytes([m[i]^k[i%len_k] for i in range(len(m))])

if __name__ == "__main__":
    m = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    k = b"ICE"
    c = key_xor(m,k)
    print(binascii.b2a_hex(c).decode())
    print(binascii.b2a_hex(c).decode() == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"\
                                          "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")