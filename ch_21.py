#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_21
"""
from util import TwisterRandom

__author__ = 'peter'


def main():
    values = [int(x.strip()) for x in open('resources/ch_21.txt') if x]
    r = TwisterRandom(1)
    print('Generating...')
    for v in values:
        n = r.extract_number()
        if v != n:
            print('{} != {}'.format(v, n))
            break
    else:
        print('All values are generated successfully!')


if __name__ == '__main__':
    main()
