#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_19
"""
import base64

import util

__author__ = 'peter'


def get_ciphertexts(key):
    result = []
    for line in open('resources/ch_19.txt'):
        d = base64.b64decode(line.strip())
        result.append(util.aes_ctr_encrypt(d, key))
    return result


def main():
    # Use static key for easy debugging
    key = b'\n\xb9\\\x1a\xb8\xca\xe5\xa3e\xec\r\x03Aw\xc5P'
    stream = []
    for i in range(10):
        stream.append(util.get_key_stream(b'\x00' * 8, i, key))
    print(stream[:3])
    # key = util.get_random_bytes(16)
    cts = get_ciphertexts(key)
    # Print statistics for the first character:
    # We see that the 'A' character has the highest frequency, as do 'T' and ']', so one of these is probably an 'E' in
    # plaintext. This means the key is probably either b'\x04', b'\x11' or b'\x18'
    char_freqs(cts, 0)
    key = [(b'\x04', b'\x11')]
    # Print statistics for the second character:
    char_freqs(cts, 1)
    # We see that b'\xd4' has the highest frequency, as does b'\xd9', so one of these is probably an 'E' in
    # plaintext. This means the key is probably either b'\x91' or b'\x9c'
    char_freqs(cts, 2)
    char_freqs(cts, 3)
    char_freqs(cts, 4)
    char_freqs(cts, 5)


def char_freqs(cts, idx):
    fs = util.text_frequencies(b''.join(x[idx].to_bytes(1, 'big') for x in cts))
    print(list(fs.items())[:3])


if __name__ == '__main__':
    main()
