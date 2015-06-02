__author__ = 'peter'


class PaddingError(Exception):
    pass


class NoValidByteFound(Exception):
    pass


class NotSeededError(Exception):
    pass


class InvalidPlaintextError(Exception):
    def __init__(self, invalid_plaintext):
        super(InvalidPlaintextError, self).__init__()
        self.invalid_plaintext = invalid_plaintext
