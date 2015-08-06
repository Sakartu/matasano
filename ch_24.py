#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_24
"""

import random
import time

import util

__author__ = 'peter'


def main():
    # Verify we can encrypt properly
    msg = util.get_random_bytes(10 * 16)
    seed = random.randint(0, (2 ** 16) - 1)
    ct = util.mt_encrypt(msg, seed)
    pt = util.mt_decrypt(ct, seed)
    if pt != msg:
        print("MT encryption/decryption doesn\'t function properly!")
        return
    else:
        print("MT encryption/decryption seems to function properly!")

    msg = util.get_random_bytes(random.randint(10, 100)) + b'A' * 14

    ct = util.mt_encrypt(msg, seed)
    # For this excercise, we assume that we "know" that the last 14 chars are 'A's. This could be a real scenario,
    # for instance in network traffic we often know the structure of the contained packet, but not all the content.
    # Because we have only a 16 bit seed, we can brute force this easily:
    print("We will now try to crack an mt_encrypt()'ed message")
    print("The (secret) seed was {}".format(seed))
    print("Brute-forcing...")
    for k in range(2 ** 16):
        candidate = util.mt_decrypt(ct, k)
        if candidate[-14:] == b'A' * 14 and seed == k:
            print("We found seed {} by brute-forcing, which is the same as the secret seed!".format(k))
            break

    # We generate a password-reset token
    print('Testing password-reset token generation and testing...')
    token = util.get_password_reset_token()
    assert util.test_password_reset_token(token, time.time())
    print('Successfully tested token as time-seeded mt_encrypted token, testing random value...')
    assert not util.test_password_reset_token(util.get_random_bytes(64), time.time())
    print('Successfully tested random value as non-time-seeded mt_encrypted token, all tests succeeded')


if __name__ == '__main__':
    main()
