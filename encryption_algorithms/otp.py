# Author: Joshua Tallman, Ryan Riccio
# Date: Sept 17th, 2022
# Program: Library to encrypt/decrypt OTP


# For encrypting and decrypting text with a One Time Pad.
class OTP(object):
    @staticmethod
    def crypt(data, key) -> tuple[bytes, bytes]:
        """
        Performs One Time Pad encryption/decryption by XORing two byte
        strings together.

        :param data: Data to be crypted.
        :type data: bytes
        :param key: Key to use for cryptions.
        :type key: bytes
        :return: tuple of the data bytes and the key bytes
        """
        # make sure we can decrypt the whole message
        # if len(data) != len(key):
        #     raise ValueError("Your key needs to be the same length as your data!")

        bit_array = OTP._bytes_to_bit_array(data)
        key_array = OTP._bytes_to_bit_array(key)

        # the operation is the same for encryption or decryption
        paired = [(d, k) for d, k in zip(bit_array, key_array)]
        crypted = [d ^ k for d, k in paired]

        crypted = OTP._bit_array_to_string(crypted)
        return crypted, key

    @staticmethod
    def crack(ciphertext) -> str:
        """
        Will crack the OTP code.

        :param ciphertext: Ciphertext to be cracked.
        :type ciphertext: bytes
        :return: str
        """
        return "Ha! You thought. You cannot crack OTP it is ambiguous :)"

    @staticmethod
    def generate_key(data) -> bytes:
        """
        Generate a proper random key with only alphanumeric characters for OTP.

        :param data: Data to generate a key for.
        :type data: bytes
        :return: bytes
        """
        import string
        import random
        import time

        random.seed(time.time())
        key = b""

        # generate a random alphanumeric character
        for ch in range(len(data)):
            key += bytes(random.choice(f'{string.ascii_letters}{string.digits}'), 'utf-8')
        return key

    # region OTP Backend
    @staticmethod
    def _bytes_to_bit_array(byte_string):
        """ Converts a string of bytes to a series of binary digits
        """
        bit_count = len(byte_string) * 8
        result = []
        for byte in byte_string:
            for bit_pos in [7, 6, 5, 4, 3, 2, 1, 0]:
                if byte & (1 << bit_pos) > 0:
                    result.append(1)
                else:
                    result.append(0)
        return result

    @staticmethod
    def _bit_array_to_string(bit_array):
        """ Converts a series of binary digits to a string of bytes
        """
        result = []
        byte = 0
        for pos in range(len(bit_array)):
            byte += bit_array[pos] << (7 - (pos % 8))
            if (pos % 8) == 7:
                result += [byte]
                byte = 0
        return bytes(result)
    # endregion
