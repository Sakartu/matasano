#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_29.py
"""
import base64
from collections import defaultdict
import hashlib
import pprint
import random
import statistics
import time
import sys
import binascii
import multiprocessing
import requests
import urllib.request
import urllib.error
import hmac

import util
import util.signature_server

__author__ = 'peter'

KEYLEN = 10

SIG_URL = 'http://localhost:9000/check_signature'
KEY_URL = 'http://localhost:9000/get_key'


def find_hmac(f, key):
    print('Determining best request duration length')
    # Determine best length
    lengths = defaultdict(list)
    for _ in range(2):
        for l in range(256):
            lengths[l.to_bytes(1, 'big')].append(time_request(SIG_URL, b'a', l.to_bytes(1, 'big')))

    # Calculate average request length
    for k in lengths:
        lengths[k] = sum(lengths[k]) / len(lengths[k])

    vals = lengths.values()
    avg = statistics.mean(vals)
    max_len = 0
    for v in vals:
        if v > avg * 10:
            max_len = v - avg

    if not max_len:
        pprint.pprint(lengths)
        print('Could not determine best request duration length!')
        return None

    print('Best request duration is determined to be {:.4f}s'.format(max_len))

    compare = util.sha1_hmac(f, key)
    sig = b''
    # Brute force each byte position
    for i in range(20):
        sig = brute_byte(i, max_len, sig, f, compare)
    return sig


def brute_byte(i, max_len, sig, f, compare):
    print('Brute-forcing byte {}'.format(i + 1))
    # Try all possible bytes
    req_times = {}
    for b in range(256):
        b = b.to_bytes(1, 'big')
        s = sig + b
        req_time = time_request(SIG_URL, f, s)
        req_times[b] = req_time
        print_compare(s, compare, end='')

    b, samples, left, right, avg = pick_byte(req_times, max_len)
    if not b:
        print_debug(sig, compare, samples, left, right, avg, req_times)

    sig += b

    print_compare(sig, compare)

    # Debugging print, check if the signature so far is correct
    if sig[:i+1] != compare[:i+1]:
        print_debug(sig, compare, samples, left, right, avg, req_times)

    return sig


def print_debug(sig, compare, samples, left, right, avg, req_times):
    print('\nPROBLEM:')
    print('sig:     {}'.format(util.to_hex(sig)))
    print('compare: {}'.format(util.to_hex(compare)))
    print('samples: {}'.format(samples))
    print('left: {}, right: {}, avg: {}'.format(left, right, avg))
    util.print_timing_dict(req_times)
    sys.exit(-1)


def print_compare(s1, s2, end='\n'):
    print('\r', util.color_compare(binascii.hexlify(s1).ljust(40, b'0'), binascii.hexlify(s2), 2), end=end)


def pick_byte(req_times, max_val):
    # We use a moving-window to calculate the desired left and right bounds for the request time.
    # The window parameter is used to determine the number of counts
    # See the documentation of local_avg.
    window = 2
    for i, (k, v) in enumerate(req_times.items()):
        samples, avg = local_avg(list(req_times.values()), i, window)
        left = avg + (0.5 * max_val)
        right = avg + (1.5 * max_val)
        if left <= v <= right:
            return k, samples, left, right, avg
    return (None,)*5


def local_avg(l, index, window) -> int:
    """
    Calculate the local average in list l around point index. All values between (index - window) and (index + window)
    will be used in the sum. If one of the bounds lies outside the list, we will make sure we still take 2*window items,
    but move the window slightly more to the left or right.
    :param l: The list to take items from
    :type l: list
    :param index: The index around which we calculate the average
    :type index: int
    :param window: 2*window items around l[index] will be taken for the average
    :type window: int
    """
    if index - window < 0:
        left = 0
        right = 2 * window
    elif index + window > len(l):
        left = len(l) - (2 * window)
        right = len(l)
    else:
        left = index - window
        right = index + window

    return l[left:right], statistics.mean(l[left:right])


def time_request(url, file, signature):
    # Firing many requests in a row sometimes leads to weird timeout issues, so we wait a bit between requests
    time.sleep(0.005)
    file = str(base64.urlsafe_b64encode(file), 'utf8')
    signature = str(base64.urlsafe_b64encode(signature), 'utf8')

    t0 = time.time()
    try:
        urllib.request.urlopen(url + '?file=' + file + '&signature=' + signature)
    except urllib.error.HTTPError:
        pass
    t1 = time.time()

    return t1 - t0


def main(delay=0.05):
    print('Starting server')
    t = multiprocessing.Process(target=util.signature_server.main, kwargs={'argv': ['--delay', str(delay), '--quiet']})
    t.daemon = True
    t.start()
    print('Server started with pid {}'.format(t.pid))

    try:
        print('Testing SHA1 HMAC implementation')
        for _ in range(1000):
            k = util.get_random_bytes(random.randint(0, 100))
            m = util.get_random_bytes(random.randint(0, 1000))
            assert util.sha1_hmac(m, k) == hmac.new(k, m, hashlib.sha1).digest()
        print('SHA1 HMAC implementation seems to perform correctly')

        k = requests.get(KEY_URL).content
        print('Secret key is', util.to_hex(k))
        f = util.get_random_bytes(random.randint(10, 100))
        print('Brute-forcing HMAC')
        hm = find_hmac(f, k)
        assert hm == util.sha1_hmac(f, k)
        print('Signature for {} is {}!'.format(f, hm))
    finally:
        print('Terminating server')
        t.terminate()
        t.join()
        print('Server terminated')


if __name__ == '__main__':
    main()
