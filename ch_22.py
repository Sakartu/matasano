#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_19
"""
import random
import time

from util import TwisterRandom

__author__ = 'peter'

def main():
    # Sleep a random amount of time
    print('Sleeping first time...')
    time.sleep(random.randint(40, 1000))

    # Seed the PRNG
    r = TwisterRandom(time.time())

    # Sleep a random amount of time
    print('Sleeping second time...')
    time.sleep(random.randint(40, 1000))

    # Get the first number from the PRNG
    v = r.extract_number()

    # Save the current time
    current_time = time.time()

    # Brute force the seed
    print('Cracking seed...')
    for i in range(1000*1000):  # Try all seeds, for every millisecond in 1000 seconds
        if v == TwisterRandom(current_time - i).extract_number():
            print('Seed was {}!'.format(current_time - i))




if __name__ == '__main__':
    main()
