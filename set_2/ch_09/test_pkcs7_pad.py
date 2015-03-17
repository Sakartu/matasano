#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
test_pkcs7_pad.py
"""

import util

__author__ = 'peter'


def main():
    assert util.pkcs7_pad(b'YELLOW SUBMARINE') == b'YELLOW SUBMARINE' + (b'\x10' * 16)
    assert util.pkcs7_pad(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE' + (b'\x04' * 4)
    assert util.pkcs7_pad(b'Python.framework/Versions/3.4/bin/python3.4 /Users') == b'Python.framework/Versions/3.4/bin/python3.4 /Users' + (b'\x02' * 2)
    assert util.pkcs7_pad(b'') == b'\x10' * 16


if __name__ == '__main__':
    main()