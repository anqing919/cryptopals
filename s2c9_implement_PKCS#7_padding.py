from Crypto.Util.Padding import pad

if __name__ == "__main__":
    str_for_pad = b"YELLOW SUBMARINE"
    str_padded = pad(str_for_pad,20)
    assert(str_padded == b"YELLOW SUBMARINE\x04\x04\x04\x04")