from collections import defaultdict, OrderedDict
from itertools import cycle
import math
from operator import itemgetter
import random
import string
import binascii

from Crypto import Random
from Crypto.Cipher import AES
import time

from exceptions import PaddingError, NotSeededError

FREQUENCIES = {
    'E': 0.1202, 'T': 0.091, 'A': 0.0812, 'O': 0.0768, 'I': 0.0731, 'N': 0.0695, 'S': 0.0628, 'R': 0.0602, 'H': 0.0592,
    'D': 0.0432, 'L': 0.0398, 'U': 0.0288, 'C': 0.0271, 'M': 0.0261, 'F': 0.023, 'Y': 0.0211, 'W': 0.0209, 'G': 0.0203,
    'P': 0.0182, 'B': 0.0149, 'V': 0.0111, 'K': 0.0069, 'X': 0.0017, 'Q': 0.0011, 'J': 0.001, 'Z': 0.0007,
}

GLOBAL_KEY = Random.new().read(16)


def single_char_xor_decrypt(msg, freq=FREQUENCIES, filter_non_printable=True):
    result_freq = defaultdict(dict)
    for key in range(256):
        result = ''.join(chr(x ^ key) for x in msg)

        # Discard results with non-printable characters if applicable
        if filter_non_printable and any(x not in string.printable for x in result):
            continue

        for c in freq:
            # Take non-printability into account. Add 1 so we never get a division by zero.
            non_print_compensation = sum(x not in string.printable for x in result) + 1
            result_freq[key][c] = result.upper().count(c) / float(len(result)) / non_print_compensation

        result_freq[key]['result'] = result
        d = bhattacharyya_distance(freq, result_freq[key])
        result_freq[key]['dist'] = d

    return sorted([(k, result_freq[k]['dist'], result_freq[k]['result']) for k in result_freq], key=itemgetter(1),
                  reverse=True)


def bhattacharyya_distance(d1, d2):
    """
    Calculate the Bhattacharyya coefficient for the two given frequency dicts. Assumes all keys in d1 are also in d2.
    A higher coefficient means that both dicts are more equal.
    :param d1: The first frequency dict to compare. Comparision is made on keys from this dict.
    :param d2: The second frequency dict to compare.
    :return: The Bhattacharyya coefficient for the two given frequency dicts, higher is better.
    """
    return sum(math.sqrt(d1[k] * d2[k]) for k in d1)


def text_frequencies(text):
    """
    Calculate the frequencies of each character in bytes() object text.
    :param text: The text to calculate character frequencies for
    :return: An OrderedDict mapping char to the frequency of occurrence in text, sorted by frequency
    """
    s = sorted(((k.to_bytes(1, 'big'), text.count(k) / len(text)) for k in set(text)), key=itemgetter(1), reverse=True)
    return OrderedDict(s)


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
        yield l[i:i + n]
        if num is not None and idx == num:
            return


def aes_ecb_encrypt(data, key, pad=True):
    if pad:
        data = pkcs7_pad(data)
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def aes_ecb_decrypt(data, key, depad=True):
    try:
        r = AES.new(key, AES.MODE_ECB).decrypt(data)
    except ValueError:
        raise
    return pkcs7_depad(r) if depad else r


def pkcs7_pad(data, block_size=16):
    l = len(data)
    count = block_size - (l % block_size)
    assert (l + count) % block_size == 0
    return bytes(data) + bytes(count.to_bytes(1, 'big') * count)


def pkcs7_depad(data):
    last = data[-1]
    if last > 0 and data.endswith(last.to_bytes(1, 'big') * last):
        return data[:-last]
    else:
        raise PaddingError()


def fixed_xor(ba1, ba2):
    """
    byte-wise XOR all entries of ba1 with entries from ba2. If ba2 is longer than ba1, the remaining entries will be
    ignored.
    :param ba1: The first sequence to get items from
    :param ba2: The second sequence to get items from
    :return: items from ba1 XOR ba2 as bytes() object.
    """
    return bytes(b1 ^ b2 for b1, b2 in zip(ba1, ba2))


def aes_cbc_decrypt(ct, key, iv=b'\x00' * 16, verbose=False):
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
        print('d, int_res:', to_hex(result))
    return pkcs7_depad(result)


def aes_cbc_encrypt(data, key, iv=b'\x00' * 16, verbose=False):
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
            ct = cipher(b'A' * i)
            if not blocksize:
                blocksize = len(ct)
            else:
                if len(ct) != blocksize:
                    return len(ct) - blocksize
    else:
        raise ValueError('Cipher is unstable, can\'t find blocksize!')


def find_repeating_block(ct, bs, minlen=2):
    cs = list(chunks(ct, bs))
    begin = 1
    blocks = []
    while begin < len(cs):
        end = begin
        for block in cs[begin + 1:]:
            if block == cs[begin]:
                end += 1
            else:
                break
        if (end - begin) + 1 >= minlen:
            blocks.append((begin, end))
        begin = end + 1
    return blocks


def to_hex(bs):
    i = iter(str(binascii.hexlify(bs), encoding='ascii'))
    return '\\x' + '\\x'.join(a + b for a, b in zip(i, i))


def get_key_stream(nonce, ctr, key):
    return aes_ecb_encrypt(nonce + ctr.to_bytes(8, 'little'), key, pad=False)


def aes_ctr_encrypt(data, key, nonce=b'\x00' * 8, debug=False):
    ctr = 0
    result = b''
    for b in chunks(data, 16):
        keystream = get_key_stream(nonce, ctr, key)
        if debug:
            print('Keystream for counter {} is {}'.format(ctr, to_hex(keystream)))
        result += fixed_xor(b, keystream)
        ctr += 1
    return result


def aes_ctr_decrypt(data, key, nonce=b'\x00' * 8, debug=False):
    return aes_ctr_encrypt(data, key, nonce, debug)


class TwisterRandom:
    def __init__(self, seed):
        self.mt = [0] * 624
        self.index = 0
        self.seed = seed
        if seed is not None:
            self._initialize_generator(seed)

    def _initialize_generator(self, seed):
        self.index = 0
        self.mt[0] = int(seed)
        for i in range(1, 624):
            self.mt[i] = (1812433253 * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i) & 0xffffffff  # 0x6c078965

    def extract_number(self):
        if self.seed is None:
            raise NotSeededError("TwisterRandom class was called with None as seed, please recreate or call clone()!")

        if not self.index:
            self._generate_numbers()

        y = self.mt[self.index]

        y ^= y >> 11
        y ^= (y << 7) & 2636928640  # 0x9d2c5680
        y ^= (y << 15) & 4022730752  # 0xefc60000
        y ^= y >> 18

        self.index = (self.index + 1) % 624
        return y

    def clone(self, numbers):
        for i in range(624):
            # Apply inverse operations of extract_number to recreate state
            n = numbers[i]
            n = self._undo_shift_a(n)
            n = self._undo_shift_b(n)
            n = self._undo_shift_c(n)
            n = self._undo_shift_d(n)

            # Set the internal state
            self.mt[i] = n
        self.seed = -1
        return self

    @staticmethod
    def _undo_shift_a(val):
        # original: y ^= y >> 18
        # This one is easy, since the shift is larger than 16, so no tampered bits remain in (val >> 18)
        return val ^ (val >> 18)

    @staticmethod
    def _undo_shift_b(val):
        # original: y ^= (y << 15) & 4022730752  # 0xefc60000
        # Only bits 1, 4, 5, 6, 8, 11, 13, and 14 were XOR'd with their shifted variant. We use the mask to select these
        # bits in the shifted val. We use the result to XOR these same bits back in val.
        a = (val << 15) & 4022730752  # 0xefc60000
        return val ^ a

    @staticmethod
    def _undo_shift_c(val):
        # original: y ^= (y << 7) & 2636928640  # 0x9d2c5680
        a = (val << 7) & 0x1680
        val ^= a
        a = (val << 7) & 0xc4000
        val ^= a
        a = (val << 7) & 0xd200000
        val ^= a
        a = (val << 7) & 0x90000000
        return val ^ a

    @staticmethod
    def _undo_shift_d(val):
        # original: y ^= y >> 11
        # This one is a bit harder than shift_a. We have to create clean bits in two steps; the first step produces
        # 11 clean bits, the second step another 11 (making 22).
        # a contains 11 clean bits and 10 tampered bits
        a = val >> 11

        # b now contains 22 clean bits and 10 tampered bits
        b = val ^ a

        # because b has 22 clean bits and 10 tampered bits, if we shift b to the right with 11, we have 21 clean bits
        # left.
        c = b >> 11
        return val ^ c

    def _generate_numbers(self):
        for i in range(624):
            y = (self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7fffffff)
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1)
            if y % 2:  # y is odd
                self.mt[i] ^= 2567483615  # 0x9908b0df


def get_password_reset_token():
    # Just use some random bytes, encrypted using mt_encrypt with time.time() as seed
    return mt_encrypt(get_random_bytes(24) + b'PASSWORD TOKEN', time.time())


def test_password_reset_token(data, t):
    for k in range(int(t), int(t) - 1000 * 60 * 2, -1):  # Try all millisecond values between t and (t-2 min.)
        pt = mt_decrypt(data, k)
        if pt.endswith(b'PASSWORD TOKEN'):
            return True
    return False


def mt_encrypt(data, seed):
    r = TwisterRandom(seed)
    result = b''
    for b in chunks(data, 4):
        k = r.extract_number().to_bytes(4, 'big')
        result += fixed_xor(b, k)
    return result


def mt_decrypt(data, seed):
    return mt_encrypt(data, seed)


class Profile:
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
