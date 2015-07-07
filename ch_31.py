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
import requests
import urllib.request
import urllib.error
import hmac

import util

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

    b = pick_byte(req_times, max_len)
    if not b:
        print_debug(sig, compare, req_times)

    sig += b

    print_compare(sig, compare)

    # Debugging print, check if the signature so far is correct
    if sig[:i+1] != compare[:i+1]:
        print_debug(sig, compare, req_times)

    return sig


def print_debug(sig, compare, req_times):
    print('PROBLEM:')
    print('sig:     {}'.format(util.to_hex(sig)))
    print('compare: {}'.format(util.to_hex(compare)))
    pprint.pprint({util.to_hex(k): v for k, v in req_times.items()})
    sys.exit(-1)


def print_compare(s1, s2, end='\n'):
    print('\r', util.color_compare(binascii.hexlify(s1).ljust(40, b'0'), binascii.hexlify(s2), 2), end=end)


def pick_byte(req_times, max_val):
    avg = statistics.mean(req_times.values())
    left = avg + (0.5 * max_val)
    right = avg + (1.5 * max_val)
    # Return the first (hopefully the only) value between left and right
    for k, v in req_times.items():
        if left <= v <= right:
            return k


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


def main():
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


if __name__ == '__main__':
    main()
