#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
single_byte_xor.py

Options:
"""
import binascii
from collections import defaultdict
import string

from docopt import docopt

__author__ = 'peter'

FREQUENCIES = {
    'E': 12.02, 'T': 9.10, 'A': 8.12, 'O': 7.68, 'I': 7.31, 'N': 6.95, 'S': 6.28, 'R': 6.02, 'H': 5.92, 'D': 4.32,
    'L': 3.98, 'U': 2.88, 'C': 2.71, 'M': 2.61, 'F': 2.30, 'Y': 2.11, 'W': 2.09, 'G': 2.03, 'P': 1.82, 'B': 1.49,
    'V': 1.11, 'K': 0.69, 'X': 0.17, 'Q': 0.11, 'J': 0.10, 'Z': 0.07,
}


def distance(d1, d2):
    d = 0
    for k in d1:
        d += abs(d1[k] - d2[k])
    return d


def main():
    args = docopt(__doc__)
    msg = bytearray.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    result_freq = defaultdict(dict)
    best_key = 1
    best_dist = 100
    for key in range(255):
        result = ''.join(chr(x ^ key) for x in msg)

        # Discard results with non-printable characters
        if any(x not in string.printable for x in result):
            continue

        for c in FREQUENCIES:
            result_freq[key][c] = result.upper().count(c) / float(len(result)) * 100.0

        result_freq[key]['result'] = result
        d = distance(FREQUENCIES, result_freq[key])
        result_freq[key]['dist'] = d
        if d < best_dist:
            best_key = key
            best_dist = d

    for k in result_freq:
        print(chr(k), result_freq[k]['dist'], result_freq[k]['result'])
    # print(chr(best_key))
    # print(result_freq[best_key]['result'])






if __name__ == '__main__':
    main()