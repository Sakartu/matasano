from collections import defaultdict, OrderedDict
from itertools import cycle
import math
from operator import itemgetter
import random
import string
import binascii
import time

from Crypto import Random
from Crypto.Cipher import AES

from exceptions import PaddingError, NotSeededError

FREQUENCIES = {
    'E': 0.1202, 'T': 0.091, 'A': 0.0812, 'O': 0.0768, 'I': 0.0731, 'N': 0.0695, 'S': 0.0628, 'R': 0.0602, 'H': 0.0592,
    'D': 0.0432, 'L': 0.0398, 'U': 0.0288, 'C': 0.0271, 'M': 0.0261, 'F': 0.023, 'Y': 0.0211, 'W': 0.0209, 'G': 0.0203,
    'P': 0.0182, 'B': 0.0149, 'V': 0.0111, 'K': 0.0069, 'X': 0.0017, 'Q': 0.0011, 'J': 0.001, 'Z': 0.0007,
}

GLOBAL_KEY = Random.new().read(16)


def single_char_xor_decrypt(msg, freq=FREQUENCIES, filter_non_printable=True):
    """
    Try to decrypt the given message which is assumed to be encrypted using a single-character XOR encryption. We use
    the frequency table above, giving the letter frequencies of the English language, to find the most-likely key
    for encryption.

    :param msg: The message to try to decrypt
    :param freq: The letter-frequency table to use, by default uses the frequencies for the English language
    :param filter_non_printable: Whether to skip keys that generate unprintable characters after decryption
    :return: A sorted list containing tuples: (key, distance from given frequency table, decrypted message). The first
    tuple is the most likely candidate key for decryption.
    """
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


def aes_cbc_decrypt(ct, key, iv=b'\x00' * 16, depad=True, verbose=False):
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
    if depad:
        return pkcs7_depad(result)
    else:
        return result


def aes_cbc_encrypt(data, key, iv=b'\x00' * 16, pad=True, verbose=False):
    if verbose:
        print('e, len(data):', len(data))
    if pad:
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


def to_hex(o):
    """
    A function to pretty-print the object o in a form of \\xff
    :param o: This can be either a bytes() object (where each character will be printed in byte-representation), an int,
    a bytearray or a string (which will be converted to a bytes() object with encoding utf8)
    :return: o, with each byte printed as \\x string as described above
    """
    if isinstance(o, str):
        o = bytes(o, encoding='utf8')

    if isinstance(o, bytes) or isinstance(o, bytearray):
        i = iter(str(binascii.hexlify(o), encoding='ascii'))
    elif isinstance(o, int):
        i = iter(hex(o)[2:])
    else:
        raise NotImplementedError('This function only works with bytes, ints or bytearray objects!')
    return '\\x' + '\\x'.join(a + b for a, b in zip(i, i))


def get_key_stream(nonce, ctr, key):
    # Use a 64 bit unsigned little endian nonce and a 64 bit little endian block count
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


def aes_ctr_edit(ct, key, offset, newtext, nonce=b'\x00' * 8, debug=False):
    orig_pt = aes_ctr_decrypt(ct, key, nonce, debug)
    new_pt = orig_pt[:offset] + newtext
    return aes_ctr_encrypt(new_pt, key, nonce, debug)


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
        return encryption_oracle(s, mode=AES.MODE_ECB, prepend=b'', append=b'')[1]

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


def is_ascii(b):
    try:
        b.decode('ascii')
        return True
    except UnicodeDecodeError:
        return False


def left_rotate(num, bits):
    """
    The left rotate function as described in the SHA specification
    :param num: The number to rotate
    :param bits: The number of bits to rotate num
    """
    return ((num << bits) | ((num & 0xffffffff) >> (32 - bits))) & 0xffffffff


def sha1(message, original_byte_len=None, state=(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)):
    """
    SHA-1 Hashing Function

    A custom SHA-1 hashing function implemented entirely in Python.
    Found this at https://github.com/ajalt/python-sha1 and adapted to use more modern python3 constructs

    :param message: The input message string to hash.
    :param state: A five-tuple containing the values for the inner state h0 upto h4. defaults to
        (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    :param original_byte_len: A function to override the original_byte_len, used when tampering SHA hashes
    :returns: A hex SHA-1 digest of the input message (without 0x prepended, like hexdigest() from hashlib)
    """

    # Pre-processing:
    message += sha1_padding(original_byte_len or len(message))

    h0, h1, h2, h3, h4 = state

    # Process the message in successive 512-bit (64 byte) chunks:
    for chunk in chunks(message, 64):
        # break chunk into sixteen 32-bit (4 byte) big-endian words
        w = [int.from_bytes(word, 'big') for word in chunks(chunk, 4)]

        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for i in range(64):
            w.append(left_rotate(w[i] ^ w[i + 2] ^ w[i + 8] ^ w[i + 13], 1))

        # Initialize hash value for this chunk:
        a, b, c, d, e = h0, h1, h2, h3, h4

        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:  # 60 <= i <= 79
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = ((left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, a, left_rotate(b, 30), c, d)

        # Add this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value (big-endian):
    return '{:08x}{:08x}{:08x}{:08x}{:08x}'.format(h0, h1, h2, h3, h4)


def sha1_padding(msglen):
    """
    Calculate the SHA1 padding for the given message length. This returns a bytes object with the following:

    - a 1 bit, 0x80
    - 0 <= k < 512 bits '0', so that the resulting message length (in bits) is congruent to 448 (mod 512)
        this leaves 64 bits for the length (see below) to make it 512 bits long in total
    - length of message (before pre-processing), in bits, as 64-bit big-endian integer

    :param msglen: The length of the message to create the padding for
    :return: The padding as specified above
    """
    return b'\x80' + b'\x00' * ((56 - (msglen + 1) % 64) % 64) + ((msglen * 8).to_bytes(8, 'big'))


def sha_mac(msg, key):
    """
    Create a MAC (message authentication code) for the given message and key. This basically calculates SHA1(key || msg)

    :param msg: The message to create the MAC for
    :param key: The key to create the MAC with
    :return: a MAC created for the given message with the given key
    """
    return sha1(key + msg)



def md4_padding(msglen):
    """
    Calculate the MD4 padding for the given message length. This returns a bytes object with the following:

    - a 1 bit, 0x80
    - 0 <= k < 512 bits '0', so that the resulting message length (in bits) is congruent to 448 (mod 512)
        this leaves 64 bits for the length (see below) to make it 512 bits long in total
    - length of message (before pre-processing), in bits, as 64-bit big-endian integer

    :param msglen: The length of the message to create the padding for
    :return: The padding as specified above
    """
    return b'\x80' + b'\x00' * ((56 - (msglen + 1) % 64) % 64) + (msglen * 8).to_bytes(8, 'little')


def md4(msg, original_byte_len=None, state=(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)):
    """
    MD4 Hashing Function

    A custom MD4 hashing function implemented entirely in Python.
    Found parts of this at http://www.acooke.org/cute/PurePython0.html, but added a lot of code myself

    :param msg: The input message string to hash.
    :param original_byte_len: A function to override the original_byte_len, used when tampering MD4 hashes
    :param state: A five-tuple containing the values for the inner state a, b, c and d. defaults to
        (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
    :returns: A hex MD4 digest of the input message (without 0x prepended, like hexdigest() from hashlib)
    """
    f = lambda x, y, z: (x & y) | (~x & z)
    g = lambda x, y, z: (x & y) | (x & z) | (y & z)
    h = lambda x, y, z: x ^ y ^ z
    # Add padding
    msg += md4_padding(original_byte_len or len(msg))

    a, b, c, d = state

    for chunk in chunks(msg, 64):
        x = [int.from_bytes(word, 'little') for word in chunks(chunk, 4)]

        aa = a
        bb = b
        cc = c
        dd = d

        round_1 = lambda a, b, c, d, k, s: left_rotate(a + f(b, c, d) + x[k], s)
        # [ABCD  0  3]  [DABC  1  7]  [CDAB  2 11]  [BCDA  3 19]
        # [ABCD  4  3]  [DABC  5  7]  [CDAB  6 11]  [BCDA  7 19]
        # [ABCD  8  3]  [DABC  9  7]  [CDAB 10 11]  [BCDA 11 19]
        # [ABCD 12  3]  [DABC 13  7]  [CDAB 14 11]  [BCDA 15 19]
        a = round_1(a, b, c, d, 0, 3)
        d = round_1(d, a, b, c, 1, 7)
        c = round_1(c, d, a, b, 2, 11)
        b = round_1(b, c, d, a, 3, 19)

        a = round_1(a, b, c, d, 4, 3)
        d = round_1(d, a, b, c, 5, 7)
        c = round_1(c, d, a, b, 6, 11)
        b = round_1(b, c, d, a, 7, 19)

        a = round_1(a, b, c, d, 8, 3)
        d = round_1(d, a, b, c, 9, 7)
        c = round_1(c, d, a, b, 10, 11)
        b = round_1(b, c, d, a, 11, 19)

        a = round_1(a, b, c, d, 12, 3)
        d = round_1(d, a, b, c, 13, 7)
        c = round_1(c, d, a, b, 14, 11)
        b = round_1(b, c, d, a, 15, 19)

        round_2 = lambda a, b, c, d, k, s: left_rotate(a + g(b, c, d) + x[k] + 0x5a827999, s)
        # [ABCD  0  3]  [DABC  4  5]  [CDAB  8  9]  [BCDA 12 13]
        # [ABCD  1  3]  [DABC  5  5]  [CDAB  9  9]  [BCDA 13 13]
        # [ABCD  2  3]  [DABC  6  5]  [CDAB 10  9]  [BCDA 14 13]
        # [ABCD  3  3]  [DABC  7  5]  [CDAB 11  9]  [BCDA 15 13]

        a = round_2(a, b, c, d, 0, 3)
        d = round_2(d, a, b, c, 4, 5)
        c = round_2(c, d, a, b, 8, 9)
        b = round_2(b, c, d, a, 12, 13)

        a = round_2(a, b, c, d, 1, 3)
        d = round_2(d, a, b, c, 5, 5)
        c = round_2(c, d, a, b, 9, 9)
        b = round_2(b, c, d, a, 13, 13)

        a = round_2(a, b, c, d, 2, 3)
        d = round_2(d, a, b, c, 6, 5)
        c = round_2(c, d, a, b, 10, 9)
        b = round_2(b, c, d, a, 14, 13)

        a = round_2(a, b, c, d, 3, 3)
        d = round_2(d, a, b, c, 7, 5)
        c = round_2(c, d, a, b, 11, 9)
        b = round_2(b, c, d, a, 15, 13)

        round_3 = lambda a, b, c, d, k, s: left_rotate(a + h(b, c, d) + x[k] + 0x6ed9eba1, s)
        # [ABCD  0  3]  [DABC  8  9]  [CDAB  4 11]  [BCDA 12 15]
        # [ABCD  2  3]  [DABC 10  9]  [CDAB  6 11]  [BCDA 14 15]
        # [ABCD  1  3]  [DABC  9  9]  [CDAB  5 11]  [BCDA 13 15]
        # [ABCD  3  3]  [DABC 11  9]  [CDAB  7 11]  [BCDA 15 15]

        a = round_3(a, b, c, d, 0, 3)
        d = round_3(d, a, b, c, 8, 9)
        c = round_3(c, d, a, b, 4, 11)
        b = round_3(b, c, d, a, 12, 15)

        a = round_3(a, b, c, d, 2, 3)
        d = round_3(d, a, b, c, 10, 9)
        c = round_3(c, d, a, b, 6, 11)
        b = round_3(b, c, d, a, 14, 15)

        a = round_3(a, b, c, d, 1, 3)
        d = round_3(d, a, b, c, 9, 9)
        c = round_3(c, d, a, b, 5, 11)
        b = round_3(b, c, d, a, 13, 15)

        a = round_3(a, b, c, d, 3, 3)
        d = round_3(d, a, b, c, 11, 9)
        c = round_3(c, d, a, b, 7, 11)
        b = round_3(b, c, d, a, 15, 15)

        a += aa
        b += bb
        c += cc
        d += dd

    a = (a & 0xffffffff).to_bytes(4, 'little')
    b = (b & 0xffffffff).to_bytes(4, 'little')
    c = (c & 0xffffffff).to_bytes(4, 'little')
    d = (d & 0xffffffff).to_bytes(4, 'little')

    return binascii.hexlify(a + b + c + d)


def hex_table(msg, l=0x10):
    """
    Format the given message as a hex table, such as the output of hd, hexdump or xxd
    :param msg: The message to format
    :param l: The length of the
    :return:
    """
    maxlen = 4
    while (16 ** maxlen) < len(msg):
        maxlen += 1

    result = ""
    for i, c in enumerate(chunks(msg, l)):
        s = ''.join(chr(x) if 32 <= x <= 126 else '.' for x in c)
        h = ' '.join('{:02x}'.format(x) for x in c)
        result += "{:0{}x}  {:{}s}  {}\n".format(i * l, maxlen, h, (l - 1) * 3 + 2, s)
    return result
