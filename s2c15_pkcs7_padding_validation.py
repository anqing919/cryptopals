def is_pkcs7_padding(bytes_data):
    # The type of index value of bytes is int.
    padding = bytes_data[- bytes_data[-1]:]
    # Get the use of all!
    try:
        return all(padding[i] == len(padding) for i in range(len(padding)))
    except IndexError as err:
        # This is not a good example of throwing an exception.
        print("The padding is not pkcs#7",err)
        return False

if __name__ == "__main__":
    print(is_pkcs7_padding(b"ICE ICE BABY\x04\x04\x04\x04"))
    print(is_pkcs7_padding(b"ICE ICE BABY\x05\x05\x05\x05"))
    print(is_pkcs7_padding(b"ICE ICE BABY\x01\x02\x03\x04"))
    # print(is_pkcs7_padding(b"ICE ICE BABY\x01\x02\x03\xff"))