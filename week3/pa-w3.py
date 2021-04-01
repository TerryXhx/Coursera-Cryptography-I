from Crypto.Hash import SHA256

def split(path, blocksize):
    """
    Split the file into blocks according to the given size.

    Input: `path`: video path
           `blocksize`: size of each block
    Output: list contain splitted blocks
    """
    with open(path, 'rb') as video:
        byte_content = video.read()
        length = len(byte_content)
        splitted = list()
        for i in range(0, length, blocksize):
            splitted.append(byte_content[i: i + blocksize])
        return splitted

def hash(blocks):
    """"
    Encrypt the splitted blocks using SHA256.

    Input: `blocks`: splitted blocks.
    Output: last hash value and hash list
    """
    hash_list = list()
    last_hash = SHA256.new(blocks[-1])
    for i in range(len(blocks) - 2, - 1, -1):
        hash_list.append((blocks[i], last_hash))
        last_hash = SHA256.new(blocks[i] + last_hash.digest())
    hash_list.reverse()
    return last_hash, hash_list

if __name__ == '__main__':
    filepaths = ['6.1.intro.mp4_download', '6.2.birthday.mp4_download']
    for path in filepaths:
        splitted_blocks = split(path, 1024)
        h0, _ = hash(splitted_blocks)
        print('h0: {}'.format(h0.hexdigest()))