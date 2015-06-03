#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_28.py
"""
import hashlib
import random

import util

__author__ = 'peter'


def main():
    print('Testing pure-python SHA1 implementation')
    for i in range(1000):
        msg = util.get_random_bytes(150)
        assert util.sha1(msg) == hashlib.sha1(msg).hexdigest()
    print('Pure-python SHA1 seems to perform correctly')

    msg = util.get_random_bytes(random.randint(0, 1000))
    key = util.get_random_bytes(16)
    hmac = util.sha_mac(msg, key)
    print('HMAC for random message is {}'.format(hmac))
    print('Testing message tampering')
    assert hmac != util.sha_mac(util.fixed_xor(msg, util.get_random_bytes(len(msg))), key)
    print('Message tamper test succeeded, testing hmac creation')
    for k in (util.get_random_bytes(16) for _ in range(1000)):
        assert hmac != util.sha_mac(msg, k)
    print('HMAC could not be reproduced in 1000 tries with random keys, test succeeded')


if __name__ == '__main__':
    main()
