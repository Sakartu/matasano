#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
Usage:
ecb_cut_and_paste.py
"""
from profiles import Profile
import util

__author__ = 'peter'


def main():
    # Test whether profile encoding, encryption an decryption functions are working correctly:
    assert Profile.profile_for('foo@bar.com').encode() == 'email=foo@bar.com&uid=10&role=user'
    ct = Profile.profile_for('foo@bar.com').encrypt()
    assert Profile.decrypt(ct).encode() == 'email=foo@bar.com&uid=10&role=user'

    # Some examples
    email = 'foo@bar.com'
    p = Profile.profile_for(email)
    print('Profile for "{0}" is "{1}"'.format(email, p))
    print('Encoded, this is {0}\n'.format(p.encode()))

    email = 'foo@bar.com&role=admin'
    p = Profile.profile_for(email)
    print('Profile for "{0}" is "{1}"'.format(email, p))
    print('Encoded, this is {0}\n'.format(p.encode()))

    # Because we encrypt profiles using ECB and a static (but unknown) key, we can 'create' a profile with role=admin
    # To do so, we have to create a profile with data such that, at the end of the second to last block, we have
    # "role=". If we do so, the part that comes after "role=" comes in a new ECB block. We have the following length
    # distribution:
    # (len('email=') + len(x) + len('&uid=10&role=')) % 16 == 0
    # With some algebra, we can see that x can be, for instance, 13 chars long. We use 'foo1@bar1.com'.
    # This will be the first part of our crafted block.
    #
    # Then, we have to find out what the encrypted block for 'admin' is. To do so, this part should be at the beginning
    # of a block, with some garbage afterwards. Because we can only manipulate the email address, 'admin' should be part
    # of the email address. The part before 'admin' should be 16 chars long, minus len('email=') gives 10, so let's use
    # email address 'foo@ba.com' (len 10) + 'admin' (len 5). Then we combine the first two blocks of the first cipher
    # and the last block of the second cipher, concatenate those, then try to decrypt a profile from that. We use a full
    # block of padding to make sure we don't get problems there.
    first = Profile.profile_for('foo1@bar1.com').encrypt()[:32]  # ct for "email=foo1@bar1.com&uid=10&role=", len 32
    second = Profile.profile_for('foo@ba.comadmin').encrypt()[16:32]  # ct for 'admin&uid=10&rol', len 16
    pad = Profile.profile_for('fo@ba.com').encrypt()[-16:]  # ct for '\x10' * 16, padding, len 16
    assert util.aes_ecb_decrypt(first + second, util.GLOBAL_KEY, depad=False) == b'email=foo1@bar1.com&uid=10&role=admin&uid=10&rol'
    p = Profile.decrypt(first + second + pad)
    assert p.role == 'admin'
    print('Forged profile email:', p.email)
    print('Forged profile uid:', p.uid)
    print('Forged profile role:', p.role)


if __name__ == '__main__':
    main()