__author__ = 'peter'


class TwisterRandom:
    def __init__(self):
        self.mt = [0] * 624
        self.index = 0

    def initialize_generator(self, seed):
        self.index = 0
        self.mt[0] = seed
        for i in range(1, 624):
            self.mt[i] = (1812433253 * (self.mt[i-1] ^ (self.mt[i-1] >> 30)) + i) & 0xffffffff
            
    def extract_number(self):
        if not self.index:
            self._generate_numbers()

        y = self.mt[self.index]

        y ^= y >> 11
        y ^= (y << 7) & 2636928640
        y ^= (y << 15) & 4022730752
        y ^= y >> 18

        self.index = (self.index + 1) % 624
        return y

    def _generate_numbers(self):
        for i in range(624):
            y = (self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7fffffff)
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1)
            if y % 2:  # y is odd
                self.mt[i] ^= 2567483615
