#!/usr/bin/env python
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

FIXED_PREPEND = (
    b'\xbf\xa8\x9c\x81\x8b\x8f^wa}\xee\x0c\x0e~\xe0Bmg\xa7\x90Q\x8cX\xd9\xc6w\x13l2\x0c'
    b'\x03\xdb\xdc\x94\xcb\x9f\x9a.\n\xc0\x80\xe9\xea%e\xa5\xe9\x83:\xd6XNV\x181\x06\xa0'
    b'\xf7V\xe0\x10"\x8c;\xdcjz5f\xd33w\x11\x10\xa2\x0bi\xe7\xdf\xc9SA\xb7m\xd9\xa2\xd5N'
    b'\x8f\x8bs5|l\xe7i\xb4\xa6>\xa9@\x9c\xf04N\x9b$\xba.\\\x04\xa7\x0b\xc2\xf8(\x87\xdd'
    b'R\x90]\xa4\xfd\xa3\xe2N\x01m\xedK\x06j\xd5\x1f\xaci\xb9a]^\x98\xe235r\x03\xba&\x82{'
    b'\xda\xe0\x15\xaaf;IqS}\xab\xc8\r\xc97\xdf7\x16\x9a2\xf9\xda\xef\x0bm\x8f&9\xd6\xbc'
    b'\x01\xe8\'7p4\xe1d#\x94\xa16l\xd5\xcb\x7f\xf6C8~\x96\xe90\x11\x10r\x1ep\x8b\xed\xee'
    b'\xf5\xca\xa9O\xd4P\x16\xba\xa8?V\xf8\xde\xac~\x92IPS\xe1\x00\xfb\x0c\xa0\xe6$\r\x8a'
    b'\xf5r\x8e\x8dS\r\n\x1a\xc5?\x91\xb3\x15\xae\x86Y\x0f\xcc\xaaX\x94W\x9fZ\x14\xed\xb2'
    b'\x95.\xfc\xdb\x82\xf22\xf8+\xdb\xba\x8f\xd3\xb9\x9e\xdf4_d\xcb3c\xeb\x9f\x1a7E/\xab'
    b'\xd2\x7f\x8c@A\x04s\x9dS\xeb\xf5O\xc9\xc0\xfa$\xdfrr\xd3\xf4\xe8\x80^\xf8\xb0>\x15'
    b'\xfd\xce\xee\n\x0e\x85-X3\x92\xb4\xf9\xb9\x8fZzX\x86N\xfbKj\x1ch\xcb\xb7\xdcE\x9c'
    b'\x85\xf6\xca]\x81\xd8^\x92\xe0\xba\x8ek\x08#[\xce\x9c\xaf\xdf_X4\xbd\xcf\xc2\xbdh'
)
# FIXED_PREPEND = util.get_random_bytes(random.randint(1, 1000))


def main():
    def cipher(data):
        return util.encryption_oracle(data, mode=AES.MODE_ECB, prepend=FIXED_PREPEND, append=EXTRA_MSG)[1]

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
    assert (prepad + len(FIXED_PREPEND)) % blocksize == 0
    print('We need {0} bytes of padding to align the prefix'.format(prepad))

    pre_blocks = repeats[0][0]
    align_bytes = b'A' * prepad
    assert pre_blocks * blocksize == len(FIXED_PREPEND) + len(align_bytes)

    print('Prefix is {0} blocks long'.format(pre_blocks))
    print('Empty ciphertext is {0} blocks long'.format(int(len(cipher(b'')) / blocksize)))

    num_blocks = (int(len(cipher(b'')) / blocksize)) - pre_blocks
    print('The extra message contains {0} blocks'.format(num_blocks))

    secret = b''
    for num_block in range(pre_blocks, pre_blocks + num_blocks):
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
            except KeyError:
                # We are done or we didn't find a match (when we occur padding)
                break
    print(len(secret), secret)
    print(len(EXTRA_MSG), EXTRA_MSG)


if __name__ == '__main__':
    main()