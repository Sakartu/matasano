#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
test_pkcs7_pad.py
"""

import util

__author__ = 'peter'


data = [
    (b'YELLOW SUBMARINE', 16, b'\x10' * 16),
    (b'YELLOW SUBMARINE', 20, b'\x04' * 4),
    (b'Python.framework/Versions/3.4/bin/python3.4 /Users', 16, b'\x0e' * 14),
    (b'', 16, b'\x10' * 16),
    (b'A' * 160, 16, b'\x10' * 16),
    (b'A' * 158, 16, b'\x02' * 2)
]


def main():
    for i, l, p in data:
        try:
            assert util.pkcs7_pad(i, l) == i + p
        except AssertionError:
            print(i, l, p)
            raise
    else:
        print('All good!')


if __name__ == '__main__':
    main()