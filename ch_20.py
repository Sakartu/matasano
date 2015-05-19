#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_19
"""
import base64
import binascii
import util

__author__ = 'peter'


def get_ciphertexts(key):
    result = []
    debug = True
    for line in open('resources/ch_20.txt'):
        d = base64.b64decode(line.strip())
        result.append(util.aes_ctr_encrypt(d, key, debug=debug))
        debug = False
    return result


def truncate(cts, l):
    return [x[:l] for x in cts]


def main():
    # Use static key for easy debugging
    key = b'sf\x13\xf5H\xe3\xda\xa4Dl[\xda>\xc8\xc5\xee'
    testmsg = util.get_random_bytes(16*8)
    assert util.aes_ctr_decrypt(util.aes_ctr_encrypt(testmsg, key), key) == testmsg
    cts = get_ciphertexts(key)
    keysize = min(len(x) for x in cts)
    print("Shortest ct is {} bytes".format(keysize))
    cts = truncate(cts, keysize)
    print("Keysize is {} bytes".format(keysize))
    assert min(len(x) for x in cts) == max(len(x) for x in cts) == keysize

    # Create blocks with all first chars, all second chars, etc
    transposed = list(zip(*cts))

    key = b''
    for block in transposed:
        result = util.single_char_xor_decrypt(bytearray(block), filter_non_printable=False)
        c, d, r = result[0]
        key += c.to_bytes(1, 'big')
    print('Most probable keystream: {0}'.format(key))
    print('(Partially) decrypted messages:')
    for c in cts:
        print(util.fixed_xor(bytearray(c), bytearray(key)))


if __name__ == '__main__':
    main()