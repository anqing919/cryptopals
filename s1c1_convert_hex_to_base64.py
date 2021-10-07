import binascii

def convert_hex_to_base64(hex):
    bytes_value = binascii.a2b_hex(hex)
    return binascii.b2a_base64(bytes_value)

if __name__ == "__main__":
    print(convert_hex_to_base64(b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
    print(convert_hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").decode().strip())
