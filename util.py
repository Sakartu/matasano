from collections import defaultdict
from itertools import cycle
import math
from operator import itemgetter
import random
import string
from Crypto import Random
from Crypto.Cipher import AES


FREQUENCIES = {
    'A': 0.0812, 'B': 0.0149, 'C': 0.0271, 'D': 0.0432, 'E': 0.1202, 'F': 0.023, 'G': 0.0203, 'H': 0.0592, 'I': 0.0731,
    'J': 0.001, 'K': 0.0069, 'L': 0.0398, 'M': 0.0261, 'N': 0.0695, 'O': 0.0768, 'P': 0.0182, 'Q': 0.0011, 'R': 0.0602,
    'S': 0.0628, 'T': 0.091, 'U': 0.0288, 'V': 0.0111, 'W': 0.0209, 'X': 0.0017, 'Y': 0.0211, 'Z': 0.0007,
    }


GLOBAL_KEY = b'\xe0\xa4\thK\x8bcr\x9d\xa5\xd4\x87\xaa\x1f\xe7`'


def single_char_xor_decrypt(msg, freq=FREQUENCIES, filter_non_printable=True):
    result_freq = defaultdict(dict)
    for key in range(255):
        result = ''.join(chr(x ^ key) for x in msg)

        # Discard results with non-printable characters if applicable
        if filter_non_printable and any(x not in string.printable for x in result):
            continue

        for c in FREQUENCIES:
            # Take non-printability into account. Add 1 so we never get a division by zero.
            non_print_compensation = sum(x not in string.printable for x in result) + 1
            result_freq[key][c] = result.upper().count(c) / float(len(result)) / non_print_compensation

        result_freq[key]['result'] = result
        d = bhattacharyya_distance(freq, result_freq[key])
        result_freq[key]['dist'] = d

    return sorted([(chr(k), result_freq[k]['dist'], result_freq[k]['result']) for k in result_freq], key=itemgetter(1), reverse=True)


def bhattacharyya_distance(d1, d2):
    """
    Calculate the Bhattacharyya coefficient for the two given frequency dicts. Assumes all keys in d1 are also in d2.
    A higher coefficient means that both dicts are more equal.
    :param d1: The first frequency dict to compare. Comparision is made on keys from this dict.
    :param d2: The second frequency dict to compare.
    :return: The Bhattacharyya coefficient for the two given frequency dicts, higher is better.
    """
    d = 0.0
    for k in d1:
        d += math.sqrt((d1[k] / 100.0) * (d2[k] / 100.0))
    return d


def repeating_xor_decrypt(key, msg):
    repeating_key = cycle(key)
    result = ''
    for k, c in zip(repeating_key, msg):
        result += chr(ord(k) ^ c)
    return result


def chunks(l, n, num=None):
    """ Yield successive n-sized chunks from l. If num is an integer, yield max num results.
    """
    for idx, i in enumerate(range(0, len(l), n)):
        yield l[i:i+n]
        if num is not None and idx == num:
            return


def aes_ecb_encrypt(data, key, pad=True):
    if pad:
        data = pkcs7_pad(data)
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def aes_ecb_decrypt(data, key, depad=True):
    r = AES.new(key, AES.MODE_ECB).decrypt(data)
    return pkcs7_depad(r) if depad else r


def pkcs7_pad(data, block_size=16):
    l = len(data)
    count = block_size - (l % block_size)
    assert (l + count) % block_size == 0
    return bytes(data) + bytes(count.to_bytes(1, 'big') * count)


def pkcs7_depad(data):
    last = data[-1]
    if data.endswith(last.to_bytes(1, 'big') * last):
        return data[:-data[-1]]
    else:
        raise ValueError('Padding invalid!')


def fixed_xor(ba1, ba2):
    return bytes(b1 ^ b2 for b1, b2 in zip(ba1, ba2))


def aes_cbc_decrypt(ct, key, iv=b'\x00'*16, verbose=False):
    if verbose:
        print('d, len(ct):', len(ct))
    blocks = list(chunks(ct, 16))
    if verbose:
        print('d, # blocks:', len(blocks))
    result = b''
    for b in blocks:
        decrypted = aes_ecb_decrypt(b, key, depad=False)
        result += fixed_xor(decrypted, iv)
        iv = b
    if verbose:
        print('d, len(pt):', len(result))
    return pkcs7_depad(result)


def aes_cbc_encrypt(data, key, iv=b'\x00'*16, verbose=False):
    if verbose:
        print('e, len(data):', len(data))
    data = pkcs7_pad(data)
    if verbose:
        print('e, len(data) + pad:', len(data))
    blocks = list(chunks(data, 16))
    if verbose:
        print('e, # blocks:', len(blocks))
    ct = b''
    for b in blocks:
        to_encrypt = fixed_xor(b, iv)
        prev_ciph = aes_ecb_encrypt(to_encrypt, key, pad=False)
        if verbose:
            print('e, len(enc_block):', len(prev_ciph))
        ct += prev_ciph
        iv = prev_ciph
    if verbose:
        print('e, len(ct):', len(ct))
    return ct


def get_random_bytes(length=1):
    """
    Return length (default 1) random bytes
    :param length: The number of bytes to return
    :return: length random bytes
    """
    return Random.new().read(length)


def encryption_oracle(data, key=GLOBAL_KEY, mode=None, prepend=None, append=None):
    if prepend is None:
        # If prepend isn't given, prepend between 5 and 10 random bytes
        prepend = get_random_bytes(random.randint(5, 10))
    if append is None:
        # If append isn't given, append between 5 and 10 random bytes
        append = get_random_bytes(random.randint(5, 10))

    data = prepend + data + append

    if mode is None:
        # Use the given mode, or a random pick between cbc and ecb
        mode = random.choice((AES.MODE_CBC, AES.MODE_ECB))

    if mode == AES.MODE_CBC:
        ct = aes_cbc_encrypt(data, key, get_random_bytes(16))
    else:
        ct = aes_ecb_encrypt(data, key)

    return mode, ct


def detect_ecb(ct):
    cs = list(chunks(ct, 16))
    return len(set(cs)) != len(cs)


def detect_ecb_or_cbc(ct):
    if detect_ecb(ct):
        return AES.MODE_ECB
    else:
        return AES.MODE_CBC


def detect_blocksize(cipher):
    # See if cipher is stable
    stable = True
    l = len(cipher(b'A'))
    for i in range(100):
        stable = stable and len(cipher(b'A')) == l

    if stable:
        blocksize = 0
        # for challenge 12
        for i in range(1, 512):
            ct = cipher(b'A'*i)
            if not blocksize:
                blocksize = len(ct)
            else:
                if len(ct) != blocksize:
                    return len(ct) - blocksize
    else:
        raise ValueError('Cipher is unstable, can\'t find blocksize!')


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


def find_repeating_block(ct, bs, minlen=2):
    cs = list(chunks(ct, bs))
    begin = 1
    blocks = []
    while begin < len(cs):
        end = begin
        for block in cs[begin+1:]:
            if block == cs[begin]:
                end += 1
            else:
                break
        if (end - begin) + 1 >= minlen:
            blocks.append((begin, end))
        begin = end + 1
    return blocks


def cbc_enc_ch_16(plain, prepend=None, append=None):
    if prepend is None:
        prepend = "comment1=cooking%20MCs;userdata="
    if append is None:
        append = ";comment2=%20like%20a%20pound%20of%20bacon"
    plain = plain.translate(str.maketrans('', '', ';='))
    plain = prepend + plain + append
    return aes_cbc_encrypt(bytes(plain, 'utf8'), GLOBAL_KEY)


def cbc_dec_ch_16(ct, check=b';admin=true;'):
    pt = aes_cbc_decrypt(ct, GLOBAL_KEY)
    return check in pt
