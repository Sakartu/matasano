#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_22
"""
import random
import time

from util import TwisterRandom

__author__ = 'peter'


def main():
    # Sleep a random amount of time
    w = random.randint(40, 1000)
    print('Sleeping first time ({} seconds)...'.format(w))
    time.sleep(w)

    # Seed the PRNG
    print('Seeding...')
    r = TwisterRandom(time.time())

    # Sleep a random amount of time
    w = random.randint(40, 1000)
    print('Sleeping second time ({} seconds)...'.format(w))
    time.sleep(w)

    # Get the first number from the PRNG
    v = r.extract_number()

    # Save the current time
    current_time = time.time()

    # Brute force the seed
    print('Cracking seed...')
    for i in range(1000 * 1000):  # Try all seeds, for every millisecond in 1000 seconds
        if v == TwisterRandom(current_time - i).extract_number():
            print('Successfully cracked, seed was {}!'.format(int(current_time - i)))
            break
    else:
        print('Couldn\'t crack seed!')


if __name__ == '__main__':
    main()
