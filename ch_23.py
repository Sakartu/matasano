#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_23
"""

from util import TwisterRandom

__author__ = 'peter'


def main():
    print('Creating master PRNG')
    r1 = TwisterRandom(200)
    nrs = [r1.extract_number() for _ in range(624)]

    print('Cloning into slave PRNG')
    r2 = TwisterRandom(None).clone(nrs)

    print('Comparing internal states')
    if r1.mt != r2.mt or r1.index != r2.index:
        print('Internal states differ!')
    else:
        print('Internal states are consistent!')


if __name__ == '__main__':
    main()
