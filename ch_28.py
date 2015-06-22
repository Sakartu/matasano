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
        assert util.sha1(msg) == hashlib.sha1(msg).digest()
    print('Pure-python SHA1 seems to perform correctly')

    msg = util.get_random_bytes(random.randint(0, 1000))
    key = util.get_random_bytes(16)
    mac = util.sha1_mac(msg, key)
    print('MAC for random message is {}'.format(mac))
    print('Testing message tampering')
    for m in (util.get_random_bytes(len(msg)) for _ in range(1000)):
        assert mac != util.sha1_mac(util.fixed_xor(msg, m), key)
    print('Message tamper test succeeded, could not create same MAC in 1000 tries')
    print('Testing MAC creation')
    for k in (util.get_random_bytes(16) for _ in range(1000)):
        assert mac != util.sha1_mac(msg, k)
    print('MAC could not be reproduced in 1000 tries with random keys, test succeeded')


if __name__ == '__main__':
    main()
