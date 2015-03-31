from Crypto.Cipher import AES
from util import encryption_oracle, aes_ecb_decrypt, GLOBAL_KEY

__author__ = 'peter'


class Profile():
    def __init__(self, email, uid, role):
        self.email = email
        self.uid = uid
        self.role = role

    def encode(self):
        return '&'.join('{0}={1}'.format(k, getattr(self, k)) for k in ('email', 'uid', 'role'))

    def encrypt(self):
        s = bytes(self.encode(), 'utf8')
        _, ct = encryption_oracle(s, mode=AES.MODE_ECB, prepend=b'', append=b'')
        return ct


    @staticmethod
    def parse_cookie(cookie):
        result = {}
        for part in cookie.split('&'):
            if '=' not in part:
                continue
            k, v = part.split('=')
            result[k] = v
        return result


    @staticmethod
    def profile_for(email, uid=10, role='user'):
        email = email.translate(str.maketrans('', '', '&='))
        return Profile(email, uid, role)


    @staticmethod
    def decrypt(ct):
        pt = aes_ecb_decrypt(ct, GLOBAL_KEY)
        s = Profile.parse_cookie(pt.decode('utf8'))
        if 'email' in s and 'uid' in s and 'role' in s:
            return Profile(s['email'], s['uid'], s['role'])
        else:
            raise ValueError('Couldn\'t create profile for {0}'.format(s))

    def __repr__(self):
        return str(vars(self))