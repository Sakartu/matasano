#!/usr/bin/env python3
import base64
import random
from bottle import request, run, response, get
import time
import itertools
import util

__author__ = 'peter'


KEY = util.get_random_bytes(random.randint(0, 100))


@get('/check_signature')
def check_signature():
    file = base64.urlsafe_b64decode(request.query.file)
    sig = base64.urlsafe_b64decode(request.query.signature)
    if not insecure_compare(file, sig):
        response.status = 500
        return 'Boo!'
    else:
        return 'Yay!'


@get('/get_key')
def get_key():
    return KEY


def insecure_compare(file, sig):
    s = util.sha1_hmac(file, KEY)
    print(util.to_hex(sig))
    print(util.to_hex(s))
    for b1, b2 in itertools.zip_longest(s, sig):
        if b1 != b2:
            return False
        time.sleep(0.05)
    return True


run(host='localhost', port='9000')
