# Author: Ryan Riccio
# Date: Sept 29th, 2022
# Program: For storing information about the key for a Substitution cipher
class Key(object):
    DEFAULT_ALPHABET = "abcdefghijklmnopqrstuvwxyz "

    def __init__(self, key, alphabet=DEFAULT_ALPHABET):
        self.alphabet = alphabet
        self.key = key

        # create look up tables for cipher alphabet
        self._encryption_table = str.maketrans(alphabet.upper() + alphabet.lower(), key.upper() + key.lower())
        self._decryption_table = str.maketrans(key.upper() + key.lower(), alphabet.upper() + alphabet.lower())

    # getters and setters
    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key):
        self._key = key.lower()

    @property
    def alphabet(self):
        return self._alphabet

    @alphabet.setter
    def alphabet(self, alphabet):
        self._alphabet = alphabet.lower()

    # validate cipher alphabet
    def check_input(self):
        """ Check to make sure the key and alphabet are compatible. """
        if len(set(self.alphabet)) != len(set(self.key)):
            raise ValueError("The length of the key and the alphabet must be the same.")

    # use LUTs to encrypt/decrypt
    def decrypt(self, ciphertext):
        """
        Use translation table to decrypt substitution cipher.

        :param str ciphertext: ciphertext to decrypt.
        :return: plaintext
        :rtype: str
        """
        return ciphertext.translate(self._decryption_table)

    def encrypt(self, plaintext):
        """
        Use translation table to encrypt substitution cipher.

        :param str plaintext: plaintext to encrypt
        :return: ciphertext
        :rtype: str
        """
        return plaintext.translate(self._encryption_table)
