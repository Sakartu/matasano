#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
detect_ecb_cbc

Options:
"""
from Crypto.Cipher import AES

import util

__author__ = 'peter'


modes = {
    AES.MODE_ECB: 'ECB',
    AES.MODE_CBC: 'CBC',
}


def main():
    print('det', 'rel', 'match')
    for i in range(1000):
        plain = b'A' * 1000
        real_mode, ct = util.encryption_oracle(plain)
        detect_mode = util.detect_ecb_or_cbc(ct)
        print(modes[detect_mode], modes[real_mode], 'V' if real_mode == detect_mode else 'X')
        assert detect_mode == real_mode


if __name__ == '__main__':
    main()