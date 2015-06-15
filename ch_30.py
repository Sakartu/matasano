#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_29.py
"""
import hashlib
import random
import binascii

import util

__author__ = 'peter'


KEYLEN = 10


def main():
    assert util.md4(b'') == b'31d6cfe0d16ae931b73c59d7e0c089c0'
    assert util.md4(b'a') == b'bde52cb31de33e46245e05fbdbd6fb24'
    assert util.md4(b'abc') == b'a448017aaf21d8525fc10ae87aa6729d'
    assert util.md4(b'message digest') == b'd9130a8164549fe818874806e1c7014b'
    assert util.md4(b'abcdefghijklmnopqrstuvwxyz') == b'd79e1c308aa5bbcdeea8ed63df412da9'
    assert (util.md4(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') ==
            b'043f8582f241db351ce627e153e7f0e4')
    assert (util.md4(b'12345678901234567890123456789012345678901234567890123456789012345678901234567890') ==
            b'e33b4ddc9c38f2199c3e7b164fcc0536')

    # Both msg and hash are known to the attacker
    # msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    # key = util.get_random_bytes(random.randint(1, KEYLEN))  # This is *not* known to the attacker
    # mac = util.sha_mac(msg, key)
    # print('MAC is {}'.format(mac))
    #
    # # Break msg into 32-bit chunks
    # states = [int.from_bytes(c, 'big') for c in util.chunks(binascii.unhexlify(mac), 4)]
    #
    # for i, c in enumerate(states):
    #     print('h{} is {}'.format(i, hex(c)))
    #
    # admin = b';admin=true'
    #
    # # Brute force the length of the padding
    # print('Brute-forcing padding length...')
    # for l in range(1, KEYLEN + 1):
    #     glue_padding = util.sha1_padding(len(msg) + l)
    #     byte_len = l + len(msg) + len(glue_padding) + len(admin)
    #     # Left part of the if is what the server computes, right part creates the forged message
    #     # Note that the left part can use the key, but the left part cannot
    #     if util.sha_mac(msg + glue_padding + admin, key) == util.sha1(admin, byte_len, states):
    #         print('Successfully forged a valid MAC!')
    #         break
    #     l += 1
    # else:
    #     print('Couldn\'t find key!')


if __name__ == '__main__':
    main()
