#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
test_pkcs7_depad.py
"""

import util

__author__ = 'peter'


def main():
    cases = [
        (b"ICE ICE BABY\x04\x04\x04\x04", True),
        (b"ICE ICE BABY\x05\x05\x05\x05", False),
        (b"ICE ICE BABY\x01\x02\x03\x04", False),
        (b"ICE ICE BABY", False),
    ]
    for s, r in cases:
        if r:
            assert util.pkcs7_depad(s) == b"ICE ICE BABY"
        else:
            try:
                util.pkcs7_depad(s)
                raise AssertionError()
            except ValueError:
                pass


if __name__ == '__main__':
    main()
