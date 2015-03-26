#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
cbc_padding_oracle
"""
import base64
import random

import util

__author__ = 'peter'


PTS = [base64.b64decode(s) for s in
       ('MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93')]


def main():
    for _ in range(100000):
        break_cbc()


def break_cbc():
    pt, iv, key, to_decrypt = cbc_enc_ch_17()
    blocksize = 16
    ct_blocks = list(util.chunks(to_decrypt, blocksize))
    i_block = []
    print('IV:', iv, 'Key:', key)
    print('CT Blocks:', ct_blocks)
    for i in range(len(ct_blocks)):
        i_block.append([None]*blocksize)

    for ct_block_idx, ct_block in enumerate(ct_blocks):
        print('Working on block {0} ({1})'.format(ct_block_idx, ct_block))
        # Use a list of lists to know which bytes to avoid for which location
        ct_idx = 0
        while ct_idx < len(ct_block):
            ct_val = ct_block[::-1][ct_idx]
            print('Val:', ct_val, 'idx:', ct_idx)
            known_values = [x for x in i_block[ct_block_idx] if x is not None]
            # Loop values for single byte that we're going to guess
            r = brute_single_byte(blocksize, iv, key, ct_idx, ct_block, known_values)
            if r is not None:
                i_block[ct_block_idx][-ct_idx-1] = r
                ct_idx += 1
            else:
                # We couldn't find a matching byte, so the previous two bytes are probably wrong. Retry with a different
                # base block
                print('Couldn\'t find matching byte, erase results and retry with different base.')
                i_block[ct_block_idx] = [None] * blocksize
                ct_idx = 0

    pt = b''
    for l1, l2 in zip([iv] + ct_blocks, i_block):
        for a, b in zip(l1, l2):
            pt += (a ^ b).to_bytes(1, 'big')
    print('Plaintext was:', pt)


def brute_single_byte(blocksize, iv, key, idx, ct_block, known_values):
    # Compensate for starting at 0
    idx += 1
    # First set of bytes
    base = util.get_random_bytes(blocksize - idx)
    # Rest of the bytes to make valid padding
    pad = b''
    for b in known_values:
        pad += (idx ^ b).to_bytes(1, 'big')

    for i in range(256):
        b = i.to_bytes(1, 'big')
        ct = base + b + pad + ct_block
        if not len(ct) % blocksize == 0:
            print(ct)
            raise AssertionError('CT is not a multiple of blocksize!')
        if cbc_dec_ch_17(ct, key, iv):
            return i ^ idx
    print('base', base, 'pad', pad, 'ct_block', ct_block)
    return None


def cbc_enc_ch_17():
    idx = random.randint(0, len(PTS) - 1)
    # idx = 4
    pt = PTS[idx]
    iv = util.get_random_bytes(16)
    # iv = b'\x00' * 16
    # iv = b'\x01\xdf\xa4\xe1]\xaa\xfd\t_\xd2\xcc\xfbN]\xb4\x87'
    key = util.GLOBAL_KEY
    # key = b'\x9f;nb\xc1\xe3\x1c\xd9\xf6p\x08\xf7;\xe76\xa7'
    return pt, iv, key, util.aes_cbc_encrypt(pt, key, iv=iv)


def cbc_dec_ch_17(ct, key, iv):
    try:
        util.aes_cbc_decrypt(ct, key, iv)
        return True
    except util.PaddingError:
        return False


if __name__ == '__main__':
    main()