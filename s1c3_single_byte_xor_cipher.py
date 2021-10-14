import binascii

def get_english_score(bytes):
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(chr(byte),0) for byte in bytes.lower()])

def bruteforce_single_char_xor(ct):
    potential_results = []
    for k in range(0x00,0x100):
        pt = bytes([i^k for i in ct])
        score = get_english_score(pt)
        data = {
            "key" : k,
            "pt" : pt,
            "score" : score            
        }
        potential_results.append(data)
    return sorted(potential_results,key = lambda x:x["score"],reverse = True)[0]

if __name__ == "__main__":
    ct = binascii.a2b_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    print((bruteforce_single_char_xor(ct)["pt"]).decode())