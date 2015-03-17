from collections import defaultdict
from itertools import cycle
import math
from operator import itemgetter
import string
from Crypto import Random
from Crypto.Cipher import AES


FREQUENCIES = {
    'A': 0.0812, 'B': 0.0149, 'C': 0.0271, 'D': 0.0432, 'E': 0.1202, 'F': 0.023, 'G': 0.0203, 'H': 0.0592, 'I': 0.0731,
    'J': 0.001, 'K': 0.0069, 'L': 0.0398, 'M': 0.0261, 'N': 0.0695, 'O': 0.0768, 'P': 0.0182, 'Q': 0.0011, 'R': 0.0602,
    'S': 0.0628, 'T': 0.091, 'U': 0.0288, 'V': 0.0111, 'W': 0.0209, 'X': 0.0017, 'Y': 0.0211, 'Z': 0.0007,
    }


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


def aes_ecb_encrypt(data, key):
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def aes_ecb_decrypt(data, key):
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def pkcs7_pad(data, block_size=16):
    if len(data) < block_size:
        count = block_size - len(data)
    else:
        count = len(data) % block_size or block_size
    return data + (count.to_bytes(1, 'big') * count)


def fixed_xor(ba1, ba2):
    return bytes(b1 ^ b2 for b1, b2 in zip(ba1, ba2))


def get_random_key(length=16):
    return Random.new().read(length)