#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ch_35.py
"""
import random
import textwrap
import sys
import util

__author__ = 'peter'


def main():
    print('Generating session key(s)')
    # Set p and g to the NIST specified parameters
    p = int(textwrap.dedent('''
    ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
    fffffffffffff''').replace('\n', ''), 16)
    g = 2

    print('Trying MITM for g = 1')
    bot = util.DHGTamperedGBot(1)
    try_mitm(p, g, bot)

    print('Succeeded, trying for g = p')
    bot = util.DHGTamperedGBot(p)
    try_mitm(p, g, bot)

    print('Succeeded, trying for g = p-1')
    bot = util.DHGTamperedGBot(p-1)
    try_mitm(p, g, bot)
    print('All MITM\'s successful!')


def try_mitm(p, g, bot):
    p, g = bot.negotiate_pg(p, g)

    # Generate our own private and public key
    own_priv, own_pub = util.dh_gen_keypair(p, g)

    other_pub = bot.init_session(own_pub)
    session_key = util.dh_gen_session_key(p, own_priv, other_pub)

    assert session_key == bot.target.session_key
    assert session_key in bot.session_keys

    data = util.get_random_bytes(random.randint(10, 50))
    print('A: Message is {}'.format(util.to_hex(data)))
    own_iv = util.get_random_bytes(16)
    ct = util.aes_cbc_encrypt(data, session_key, own_iv)
    msg = bot.echo(ct + own_iv)
    other_ct, other_iv = msg[:-16], msg[-16:]
    assert data == util.aes_cbc_decrypt(other_ct, session_key, other_iv)

if __name__ == '__main__':
    main()
