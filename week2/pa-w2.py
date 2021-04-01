from Crypto.Cipher import AES

def hexxor(a, b):     
    # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(x ^ y) for (x, y) in zip(a[:len(b)], b)])
    else:
       return "".join([chr(x ^ y) for (x, y) in zip(a, b[:len(a)])])

def decrypt_CBC(ciphertext, key):
    bs = AES.block_size
    if len(ciphertext) <= bs:
        return ciphertext
    iv = ciphertext[: bs]
    cipher = AES.new(key, AES.MODE_ECB)
    unpad = lambda s : s[0:-ord(s[-1])]
    message = ''
    
    for i in range(1, len(ciphertext) // bs):
        cur = hexxor(cipher.decrypt(ciphertext[i * bs: (i + 1) * bs]), iv)
        iv = ciphertext[i * bs: (i + 1) * bs]
        message += cur
    return unpad(message)

def decrypt_CTR(ciphertext, key):
    def hexstr_plus_one(str):
        return str[: -1] + bytes.fromhex(hex((str[-1] + 1) % 256)[2:])
    bs = AES.block_size
    if len(ciphertext) <= bs:
        return ciphertext
    iv = ciphertext[: bs]
    cipher = AES.new(key, AES.MODE_ECB)
    message = ''

    for i in range(1, len(ciphertext) // bs):
        iv_enc = cipher.encrypt(iv)
        cur = hexxor(ciphertext[i * bs: (i + 1) * bs], iv_enc)
        iv = hexstr_plus_one(iv)
        message += cur
    
    if len(ciphertext) % bs != 0:
        iv_enc = cipher.encrypt(iv)
        cur = hexxor(ciphertext[len(ciphertext) // bs * bs: ], iv_enc)
        message += cur
    return message

def main():
    # CBC mode
    print('CBC mode: ')
    key_CBC = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')
    ct1 = bytes.fromhex('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')
    ct2 = bytes.fromhex('5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')
    print('plain text1:', decrypt_CBC(ct1, key_CBC))
    print('plain text2:', decrypt_CBC(ct2, key_CBC))

    # CTR mode
    print('CTR mode: ')
    key_CTR = bytes.fromhex('36f18357be4dbd77f050515c73fcf9f2')
    ct1 = bytes.fromhex('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')
    ct2 = bytes.fromhex('770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')
    print('plain text1:', decrypt_CTR(ct1, key_CTR))
    print('plain text2:', decrypt_CTR(ct2, key_CTR))


if __name__ == '__main__':
    main()