from collections import defaultdict
import math
from operator import itemgetter
import string


FREQUENCIES = {
    'A': 0.0812, 'B': 0.0149, 'C': 0.0271, 'D': 0.0432, 'E': 0.1202, 'F': 0.023, 'G': 0.0203, 'H': 0.0592, 'I': 0.0731,
    'J': 0.001, 'K': 0.0069, 'L': 0.0398, 'M': 0.0261, 'N': 0.0695, 'O': 0.0768, 'P': 0.0182, 'Q': 0.0011, 'R': 0.0602,
    'S': 0.0628, 'T': 0.091, 'U': 0.0288, 'V': 0.0111, 'W': 0.0209, 'X': 0.0017, 'Y': 0.0211, 'Z': 0.0007,
    }


def single_char_xor_decrypt(msg, freq=FREQUENCIES):
    result_freq = defaultdict(dict)
    for key in range(255):
        result = ''.join(chr(x ^ key) for x in msg)

        # Discard results with non-printable characters
        if any(x not in string.printable for x in result):
            continue

        for c in FREQUENCIES:
            result_freq[key][c] = result.upper().count(c) / float(len(result))

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
