#!/usr/bin/env python3
"""
Usage:
signature_server.py [--host HOST] [--port PORT] [--delay DELAY] [--quiet]

Options:
--quiet             Do not print each request
--host HOST         The host to bind the server to. [default: localhost]
--port PORT         The port to bind the server to. [default: 9000]
--delay DELAY       The artificial delay (in ms) between each comparison of bytes of the signature [default: 0.05]
"""
import base64
import random
from docopt import docopt
from bottle import request, run, response, get
import time
import itertools
import sys
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
    if not quiet:
        print(util.to_hex(sig))
        print(util.to_hex(s))
    for b1, b2 in itertools.zip_longest(s, sig):
        if b1 != b2:
            return False
        time.sleep(0.05)
    return True


def main(argv=None):
    args = docopt(__doc__, argv=argv)
    global delay, quiet

    try:
        delay = float(args['--delay'])
        quiet = args['--quiet']
    except ValueError:
        print('Provided delay "{}" is no valid float!'.format(args['--delay']))
        sys.exit(-1)
    run(host=args['--host'], port=args['--port'], quiet=args['--quiet'])


if __name__ == '__main__':
    main()
