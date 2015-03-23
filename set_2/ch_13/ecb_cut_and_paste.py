#!/usr/bin/env python
# -*- coding: utf8 -*-
"""
Usage:
ecb_cut_and_paste.py
"""

import util

__author__ = 'peter'


def main():
    # Test whether profile encoding, encryption an decryption functions are working correctly:
    assert util.Profile.profile_for('foo@bar.com').encode() == 'email=foo@bar.com&role=user&uid=10'
    _, ct = util.Profile.profile_for('foo@bar.com').encrypt()
    assert util.Profile.decrypt(ct).encode() == 'email=foo@bar.com&role=user&uid=10'


if __name__ == '__main__':
    main()