#! /usr/bin/env python

from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random
import struct

class PaddingError(Exception):
    pass

def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = ''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def aes_encrypt(plaintext, password, key_length=32):
    if len(plaintext) == 0:
        return ''

    bs = AES.block_size

    # generate random salt
    salt = Random.new().read(bs)

    # save salt
    result = salt

    # derive key, iv
    key, iv = derive_key_and_iv(password, salt, key_length, bs)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    chunk = plaintext
    if len(chunk) % bs != 0:
        padding_length = (bs - len(chunk) % bs) or bs
        chunk += padding_length * chr(padding_length)

    result += cipher.encrypt(chunk)

    return result

def aes_decrypt(ciphertext, password, salt, key_length=32):
    if len(ciphertext) == 0:
        return ''

    bs = AES.block_size

    # derive key, iv
    key, iv = derive_key_and_iv(password, salt, key_length, bs)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    padding_length = ord(plaintext[-1])

    check_paddings(plaintext)

    return plaintext[:-padding_length]

def check_paddings(s):
    padding = ord(s[-1])
    if padding > 16 or padding <= 0:
        # padding error
        raise PaddingError()
    i = 2
    while i <= padding:
        if ord(s[-i]) != padding:
            # padding error
            raise PaddingError()
        i += 1


def poa(ciphertext, padding_oracle):
    bs = AES.block_size

    if len(ciphertext) < 2*bs:
        print "Invalid ciphertext"
        return

    block_num = len(ciphertext) / bs

    # Crack the last block first
    target_block = ciphertext[(block_num-1)*bs:]
    pre_block = ciphertext[(block_num-2)*bs:block_num*bs]
    plain_block = [0] * bs
    inter_block = [0] * bs
    for i in xrange(0, 0xff+1):
        mock_block = struct.pack('16B', *([0]*15 + [i]))
        if padding_oracle(mock_block+target_block):
            # check padding value
            padding_value = 1
            for next_padding_value in xrange(2, bs+1):
                mock_block = struct.pack('16B', *([0]*(bs-next_padding_value) + [1] + [0]*(next_padding_value-2) + [i]))
                if padding_oracle(mock_block+target_block):
                    break
                padding_value = next_padding_value
                print 'xxx:', padding_value
            I2 = i ^ padding_value
            inter_block[15] = I2
            # P2: the last byte of the plaintext of the target_block
            P2 = ord(pre_block[15]) ^ I2
            plain_block[15] = P2
            break

    # Crack remain bytes for the block
    for current_pos in xrange(14, -1, -1):
        padding_value = bs - current_pos
        mock_tail = [padding_value ^ I2 for I2 in inter_block[current_pos+1:]]
        for i in xrange(0, 0xff+1):
            mock_block = struct.pack('16B', *([0]*(current_pos) + [i] + mock_tail))
            if padding_oracle(mock_block+target_block):
                I2 = i ^ padding_value
                inter_block[current_pos] = I2
                P2 = ord(pre_block[current_pos]) ^ I2
                plain_block[current_pos] = P2

    print plain_block
    plaintext = ''.join([chr(v) for v in plain_block])

    # Check paddings
    check_paddings(plaintext)

    padding = ord(plaintext[-1])
    print plaintext[:-padding]

if __name__ == '__main__':
    import argparse, os

    parser = argparse.ArgumentParser(description='Padding Oracle Attack Demo.')
    parser.add_argument('--target', default='a'*30)
    parser.add_argument('-p', '--password', dest='password', default='PaddingOracleAttack')
    parser.add_argument('--key-len', type=int, default=32)
    parser.add_argument('-d', '--decrypt', dest='decrypt_flag', action='store_const', const=True, help='decrypt')

    args = parser.parse_args()
    print args

    target = args.target
    password = args.password
    key_length = args.key_len
    decrypt_flag = args.decrypt_flag

    if decrypt_flag:
        ret = aes_decrypt(target[16:], password, target[:16], key_length)
        if not ret:
            print 'Decrpt failed!'
        else:
            print ret
    else:
        ciphertext = aes_encrypt(target, password, key_length)
        print len(ciphertext)
        print aes_decrypt(ciphertext[16:], password, ciphertext[:16], key_length)


    salt = ciphertext[:16]
    ciphertext = ciphertext[16:]

    def padding_oracle(ciphertext):
        try:
            aes_decrypt(ciphertext, password, salt, key_length)
            return True
        except PaddingError:
            return False

    poa(ciphertext, padding_oracle)

