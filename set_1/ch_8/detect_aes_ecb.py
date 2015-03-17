#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
detect_aes_ecb.py INFILE

Options:
"""
from docopt import docopt
import util

__author__ = 'peter'


def main():
    args = docopt(__doc__)
    lines = [bytes.fromhex(l.strip()) for l in open(args['INFILE'])]
    for idx, line in enumerate(lines):
        cs = list(util.chunks(line, 16))
        if len(set(cs)) != len(cs):
            print("Line {} '{}' is probably encoded using ECB mode because it has a repeated block".format(idx, line))


if __name__ == '__main__':
    main()