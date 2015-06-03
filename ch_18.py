#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
test_ctr.py
"""
import base64

import util

__author__ = 'peter'


def main():
    test = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    assert util.aes_ctr_decrypt(test, b"YELLOW SUBMARINE") == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    k = util.get_random_bytes(16)
    m = b'This is an interesting message'
    assert util.aes_ctr_decrypt(util.aes_ctr_encrypt(m, k), k) == m


if __name__ == '__main__':
    main()
