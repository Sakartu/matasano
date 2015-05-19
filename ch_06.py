#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
break_repeating_xor.py INFILE

Options:
"""
import base64
import os
import string

from docopt import docopt

import util


__author__ = 'peter'


def hamming_distance(cs):
    """
    Calculates the Hamming distance over all strings in cs, in order. First the distance is calculated over the first
    two items of cs, then over the second and third items, then the third and fourth, etc. At the end, the average
    of all calculated distances is returned
    :param cs: A list of strings to calculate Hamming distance over
    :return: The average Hamming distance for all strings in cs, calculated over each pair of items in cs, in order.
    """
    d = 0.0
    end = len(cs) - 1
    for idx in range(end):
        s1 = cs[idx]
        s2 = cs[idx+1]
        assert len(s1) == len(s2)
        s1_bits = ''.join('{:b}'.format(c).zfill(8) for c in s1)
        s2_bits = ''.join('{:b}'.format(c).zfill(8) for c in s2)
        d += sum(c1 != c2 for c1, c2 in zip(s1_bits, s2_bits))
    return d / end


def main():
    args = docopt(__doc__)
    data = base64.b64decode(''.join(x for x in open(args['INFILE'])).strip())
    assert data == open(os.path.splitext(args['INFILE'])[0] + '.bytes', 'rb').read()
    candidates = []
    # Find best matching keysizes
    for keysize in range(2, 40):
        cs = tuple(util.chunks(data, keysize, 4))
        dist = hamming_distance(cs) / float(keysize)
        candidates.append((keysize, dist))
    best = sorted(candidates, key=lambda x: x[1])
    print('Best keysizes (with distances) are: {0}'.format(best))
    decrypted = []
    for keysize, _ in best[:5]:
        pieces = list(util.chunks(data, keysize))
        pieces = pieces[:-1]  # Remove last piece, as this probably isn't full length
        print('Length of the chunklist is {0}'.format(len(pieces)))
        transposed = list(zip(*pieces))
        print('Length of the transposed list is {0}'.format(len(transposed)))

        key = ''
        for block in transposed:
            result = util.single_char_xor_decrypt(bytearray(block), filter_non_printable=False)
            c, d, r = result[0]
            key += chr(c)
        decrypted.append((keysize, key, repr(util.repeating_xor_decrypt(key, data))))
    decrypted = sorted(decrypted, key=lambda x: sum(y in string.punctuation for y in x[2]))
    print('Most probable key: "{0}"'.format(decrypted[0][1]))
    print('Plaintext:', repr(decrypted[0][2]))


if __name__ == '__main__':
    main()