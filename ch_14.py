#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
byte_by_byte_ecb_hard.py

Options:
"""
import base64
import random
from Crypto.Cipher import AES
import util

__author__ = 'peter'

EXTRA_MSG = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                             'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                             'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                             'YnkK')

FIXED_PREPEND = util.get_random_bytes(random.randint(1, 1000))


def main():
    for i in range(16):
        s = break_ecb(FIXED_PREPEND + b'C' * i)
        assert s == b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\x01"


def break_ecb(prepend_data):
    def cipher(data):
        return util.encryption_oracle(data, mode=AES.MODE_ECB, prepend=prepend_data, append=EXTRA_MSG)[1]

    # Find the blocksize
    blocksize = util.detect_blocksize(cipher)
    print('Blocksize is', blocksize)

    # Find out whether the mode is ECB, if not, quit
    if not util.detect_ecb(cipher(b'A' * 500)):
        print('Cipher doesn\'t use ECB mode!')
        return
    else:
        print('Cipher uses ECB mode, cracking...')

    # Try to find out how big the prepended message is and how much bytes we need for alignment
    prepad = 0
    pattern = util.get_random_bytes(blocksize)
    blocks = 10
    repeats = None
    while prepad < blocksize:
        pt = (b'A' * prepad) + (pattern * blocks)
        ct = cipher(pt)
        repeats = util.find_repeating_block(ct, blocksize, blocks)
        if repeats:
            break
        prepad += 1
    assert (prepad + len(prepend_data)) % blocksize == 0
    print('We need {0} bytes of padding to align the prefix'.format(prepad))

    pre_blocks = repeats[0][0]

    secret = calc_secret(cipher, blocksize, prepend_data, prepad, pre_blocks)

    print(len(secret), secret)
    print(len(EXTRA_MSG), EXTRA_MSG)

    return secret


def calc_secret(cipher, blocksize, prepend_data, prepad, pre_blocks):
    align_bytes = b'A' * prepad
    assert pre_blocks * blocksize == len(prepend_data) + len(align_bytes)

    print('Prefix is {0} blocks long'.format(pre_blocks))

    empty_len = int(len(cipher(b'')) / blocksize)
    print('Empty ciphertext is {0} blocks long'.format(empty_len))

    num_blocks = (int(len(cipher(align_bytes)) / blocksize)) - pre_blocks
    print('The extra message contains {0} blocks'.format(num_blocks))

    secret = b''
    num_block = pre_blocks
    while num_block <= empty_len + 1:
        # for num_block in range(pre_blocks, pre_blocks + num_blocks + 1):
        print('Working on block number {0}'.format(num_block))
        for num_byte in range(blocksize):
            basemsg = align_bytes + b'A' * (blocksize - num_byte - 1)
            d = {}
            for i in range(255):
                b = bytes([i])
                ct = cipher(basemsg + secret + b)
                blocks = list(util.chunks(ct, blocksize))
                d[blocks[num_block]] = b
            ct = cipher(basemsg)
            try:
                secret += d[list(util.chunks(ct, blocksize))[num_block]]
            except (KeyError, IndexError):
                # We are done or we didn't find a match (when we occur padding)
                print('Break halfway')
                return secret
        num_block += 1
    return secret


if __name__ == '__main__':
    main()