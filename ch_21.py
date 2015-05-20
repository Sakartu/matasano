#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_19
"""
import base64
import binascii
from mt_random import TwisterRandom
import util

__author__ = 'peter'

def main():
    values = [int(x.strip()) for x in open('resources/ch_21.txt') if x]
    r = TwisterRandom()
    r.initialize_generator(1)
    for v in values:
        n = r.extract_number()
        if v != n:
            print('{} != {}'.format(v, n))
            break


if __name__ == '__main__':
    main()