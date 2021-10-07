import binascii

def fixed_xor(hex1,hex2):
    '''参数皆为16进制字节串，返回十六进制字节串'''
    bytes1 = binascii.a2b_hex(hex1)
    bytes2 = binascii.a2b_hex(hex2)
    if len(hex1) >= len(hex2):
        return binascii.b2a_hex(bytes([i^j for (i,j) in zip(bytes1[:len(bytes1)],bytes2)]))
        #return "".join([chr(i^j) for (i,j) in zip(bytes1[:len(bytes2)],bytes2)])
    else:
        return binascii.b2a_hex(bytes([i^j for (i,j) in zip(bytes1,bytes2[:len(bytes1)])]))

if __name__ == "__main__":
    print(fixed_xor("1c0111001f010100061a024b53535009181c","686974207468652062756c6c277320657965").decode().strip())