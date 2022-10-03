# Author: Ryan Riccio
# Date: Sept 29th, 2022
# Program: For encrypting and decrypting text with the Substitution Cipher
from encryption_algorithms.key import Key
import encryption_algorithms.cryptanalysis_wrapper as ca
import string
import random
import time


class Substitution(object):
    chars = string.ascii_lowercase + ' '

    @staticmethod
    def encrypt(plaintext, key):
        """
        Encrypt using the Substitution cipher.

        :param str plaintext: plaintext to encrypt.
        :param Key key: Key object to use.
        :return: string of ciphertext.
        :rtype: str
        """
        return key.encrypt(plaintext)

    @staticmethod
    def decrypt(ciphertext, key):
        """
        Decrypt using the Substitution cipher.

        :param str ciphertext: ciphertext to decrypt.
        :param Key key: Key object to use.
        :return: string of plaintext.
        :rtype: str
        """
        return key.decrypt(ciphertext)

    @staticmethod
    def crack(ciphertext):
        """
        Try to crack Substitution cipher.

        :param ciphertext: ciphertext to decrypt
        :return: decrypted ciphertext
        :rtype: str
        """
        return ca.crack_substitution(ciphertext)

    # region Substitution Backend
    @staticmethod
    def generate_key_from_password(password):
        """
        Generate cipher alphabet from a password.

        :param str password: password to generate alphabet from
        :return: Key object with password stored
        :rtype: Key
        """
        if len(password) < 1:
            raise AttributeError("Password must be longer than 1 character.")
        # remove duplicates
        key = "".join(dict.fromkeys(password.lower()))

        # get the idx of the last char to find where to start adding letters
        key_last_char = key[-1]
        starting_idx = Substitution.chars.rfind(key_last_char) + 1
        for idx in range(len(Substitution.chars)):
            if Substitution.chars[(starting_idx + idx) % len(Substitution.chars)] not in key:
                key += Substitution.chars[(starting_idx + idx) % len(Substitution.chars)]

        # create key from keystring
        key = Key(key, Substitution.chars)
        return key

    @staticmethod
    def generate_random_key():
        """
        Generate a random Key object.

        :return: random Key object.
        :rtype: Key
        """
        random.seed(time.time())
        key = Substitution.chars
        # unpack string to list
        key = [*key]
        # shuffle list
        random.shuffle(key)
        # convert back to str and create key
        key = "".join(key)
        key = Key(key, Substitution.chars)
        return key

    @staticmethod
    def print_cipher(key):
        cipher = list(zip(Substitution.chars, key.get_alphabetic_key()))
        for x in range(len(cipher)):
            print(f"----", end="")
        print()
        for num, x in enumerate(cipher):
            print(f"{x[0]:^3}|", end="")
        print()
        for num, x in enumerate(cipher):
            print(f"---+", end="")
        print()
        for num, x in enumerate(cipher):
            print(f"{x[1]:^3}|", end="")
        print()
        for num, x in enumerate(cipher):
            print(f"----", end="")
        print()
        # for freq in Caesar.calculate_frequencies(ciphertext):
        #     print(f"{freq:^3.0f}|", end="")
    # endregion
