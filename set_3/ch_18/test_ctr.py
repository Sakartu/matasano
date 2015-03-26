#!/usr/bin/env python
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
    print(util.aes_ctr_decrypt(test, b"YELLOW SUBMARINE"))


if __name__ == '__main__':
    main()