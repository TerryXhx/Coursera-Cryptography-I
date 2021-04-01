import requests
import time

URL = 'http://crypto-class.appspot.com/po?er='
CIPHERTEXT = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
BLOCK_SIZE = 16
PROXIES = {
    "http": "http://127.0.0.1:7890",
    "https": "https://127.0.0.1:7890"
} 
HEADERS= {
    'Connection': 'close'
}

def xor(bytes1, bytes2):
    """
    Xor two input bytes and return

    Input: `bytes1`, `bytes2`: bytes need to xor.
    Output: xor result
    """
    return bytes([a ^ b for a, b in zip(bytes1, bytes2)])

def verify_padding(ciphertext_bytes):
    """
    Verify if the padding is valid by the status code of request
    """
    try:
        req = requests.get(URL + ciphertext_bytes.hex(), proxies = PROXIES, headers = HEADERS)
        if req.status_code == 404:
            return True
        elif req.status_code == 403:
            return False
        else:
            raise Exception(f'Unexpected status code for byte: {req.status_code}')
    except:
        time.sleep(5) 
        print('sleep...')

def decrypt_byte(byte_id, target_block, prev_block, decrypted_block):
    """
    Decrypt the i-th byte of the block by verifying the padding and store the verified result into the decrypted block.

    Input: `byte_id`: the index of the byte to decrypt
           `target_block`: the block to which the decrypted byte belongs
           `prev_block`: the previous block of the target block as we need it to decrypt
           `decrypted_block`: a block for storage of decrypted data
    Output: Nothing.
    """
    padding_byte = BLOCK_SIZE - byte_id
    pad = bytes([padding_byte] * BLOCK_SIZE)

    for g in range(256):
        decrypted_block[byte_id] = g
        changed_ct_bytes = xor(decrypted_block, xor(prev_block, pad)) + target_block
        if verify_padding(changed_ct_bytes):
            print(f'Byte #{byte_id + 1}: {hex(g)}')
            return
    raise Exception(f'Fail to decrypt byte #{byte_id}')

def decrypt_block(block_id, blocks):
    """
    Using a padding oracle attack to decrypt the exact i-th block.

    Input: `block_id`: the index of the block decrypted
           `blocks`: splitted ciphertext with BLOCK_SIZE
    Output: hexadecimal plaintext of the i-th block
    """
    print(f"Decrypting block #{block_id}.")
    target_block = blocks[block_id]
    prev_block = blocks[block_id - 1]
    decrypted_block = bytearray(BLOCK_SIZE)

    # decrypt from back to front as the previous bytes need next bytes to decrypt
    for byte_id in range(BLOCK_SIZE - 1, -1, -1):
        decrypt_byte(byte_id, target_block, prev_block, decrypted_block)
    
    print(f'Hexadecimal plaintext of block #{block_id}: {decrypted_block.hex()}')
    print(f'Plaintext of block #{block_id}: \"{decrypted_block.decode("ascii")}\"') # Use parentheses to wrap the plaintext because there may be spaces at the beginning or end

    return decrypted_block

def decrypt_ciphertext(ciphertext):
    """
    Using a padding oracle attack to decrypt a ciphertext with CBC mode.

    Input: `ciphertext`: origin ciphertext
    Output: plaintext decrypted from the input  ciphertext
    """
    ct_bytes = bytes.fromhex(ciphertext)
    blocks = [ct_bytes[i: i + BLOCK_SIZE] for i in range(0, len(ct_bytes), BLOCK_SIZE)] 

    plaintext = ''
    for i in range(1, len(blocks)):
        plaintext += decrypt_block(i, blocks).hex()
    
    return plaintext

def main():
    plaintext_bytes = decrypt_ciphertext(CIPHERTEXT)
    plaintext = bytes.fromhex(plaintext_bytes).decode('ascii')
    print(f'Plaintext: "{plaintext}"')

if __name__== '__main__':
    main()
