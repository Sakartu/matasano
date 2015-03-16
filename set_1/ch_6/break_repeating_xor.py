#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
break_repeating_xor.py INFILE

Options:
"""
import base64

from docopt import docopt

__author__ = 'peter'


def hamming_distance(s1, s2):
    assert len(s1) == len(s2)
    s1_bits = ''.join('{:b}'.format(c).zfill(8) for c in s1)
    s2_bits = ''.join('{:b}'.format(c).zfill(8) for c in s2)
    return sum(c1 != c2 for c1, c2 in zip(s1_bits, s2_bits))


def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in range(0, len(l), n):
        yield l[i:i+n]


def main():
    args = docopt(__doc__)
    data = base64.b64decode(''.join(x for x in open(args['INFILE'])).strip())
    candidates = []
    for keysize in range(2, 40):
        s1 = data[0:keysize]
        s2 = data[keysize:2*keysize]
        dist = hamming_distance(s1, s2) / float(keysize)
        candidates.append((keysize, dist))
    best = sorted(candidates, key=lambda x: x[1])[:5]
    print('Best keysizes are: {0}'.format(best))
    for keysize, dist in best:
        pieces = list(chunks(data, keysize))
        pieces = pieces[:-1]
        print('Length of the chunklist is {0}'.format(len(pieces)))
        transposed = list(zip(*pieces))
        print('Length of the transposed list is {0}'.format(len(transposed)))
        for block in transposed:
            solve_single




if __name__ == '__main__':
    main()