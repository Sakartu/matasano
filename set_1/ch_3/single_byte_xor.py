#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
single_byte_xor.py MSG...
"""
from docopt import docopt
from veryprettytable import VeryPrettyTable
import util

__author__ = 'peter'



def main():
    args = docopt(__doc__)
    for m in args['MSG']:
        t = VeryPrettyTable(field_names=('chr', 'coefficient', 'decrypted'))
        t.align = 'l'
        result = util.single_char_xor_decrypt(m)
        for c, d, r in result:
            t.add_row((c, d, repr(r)))
        print(t.get_string())


if __name__ == '__main__':
    main()