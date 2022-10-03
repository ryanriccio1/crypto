# Authors: Joshua Tallman, Ryan Riccio
# Date: Sept 17th, 2022
# Program: Functions to make cryptanalysis of caesar shift cipher easier


class Caesar(object):
    @staticmethod
    def encrypt(plaintext, key) -> str:
        """
        Encrypts using the Caesar Shift Cipher with the given key.

        :param plaintext: Text to encrypt.
        :type plaintext: str
        :param key: Key for the shift amount.
        :type key: int
        :return: str
        """
        plaintext_as_ordinals = Caesar._words_to_ordinals(plaintext)
        ciphertext_as_ordinals = Caesar._caesar_shift_ordinals(plaintext_as_ordinals, key)
        ciphertext_as_list = Caesar._ordinals_to_words(ciphertext_as_ordinals)
        ciphertext = "".join(ciphertext_as_list)
        return ciphertext

    @staticmethod
    def decrypt(ciphertext, key) -> str:
        """
        Decrypts using the Caesar Shift Cipher with the given key.

        :param ciphertext: Text to decrypt.
        :type ciphertext: str
        :param key: Key for the shift amount.
        :type key: int
        :return: str
        """
        ciphertext_as_ordinals = Caesar._words_to_ordinals(ciphertext)
        plaintext_as_ordinals = Caesar._caesar_shift_ordinals(ciphertext_as_ordinals, -key)
        plaintext_as_list = Caesar._ordinals_to_words(plaintext_as_ordinals)
        plaintext = "".join(plaintext_as_list)
        return plaintext

    @staticmethod
    def crack(ciphertext) -> tuple[str, int]:
        """
        Use frequency analysis to pick the best key for a caesar shift.

        :param ciphertext: Text to crack.
        :type ciphertext: str
        :return: a tuple with the plaintext and the shift amount
        """
        scored_frequencies = Caesar.score_all_keys(ciphertext)
        sorted_dict = {k: v for k, v in sorted(scored_frequencies.items(), key=lambda item: item[1])}
        return Caesar.decrypt(ciphertext, list(sorted_dict.keys())[0]), list(sorted_dict.keys())[0]

    # region Caesar Backend
    english_alphabet = "abcdefghijklmnopqrstuvwxyz"
    english_frequencies = [8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.2, 0.8,
                           4.0, 2.4, 6.7, 7.5, 1.9, 0.1, 6.0, 6.3, 9.1, 2.8, 1.0,
                           2.4, 0.2, 2.0, 0.1]

    @staticmethod
    def _words_to_ordinals(input_string):
        """ Converts an ASCII string to a list of ordinals. Output list has the
            same number of items as the input string's length. Non-alphabetic chars
            are copied to the output without any modification (spaces, punctuation,
            numbers, etc.).
        """
        zeroed_ordinals = []
        for letter in input_string:
            if letter.isalpha():
                if letter.islower():
                    zeroed_ordinals.append(ord(letter) - ord('a'))
                else:
                    zeroed_ordinals.append(ord(letter) - ord('A'))
            else:
                zeroed_ordinals.append(letter)
        return zeroed_ordinals

    @staticmethod
    def _ordinals_to_words(input_string):
        """ Converts a list of ordinals to a list of letters. Output list has the
            same number of items as the input list's length. Non-alphabetic ordinals
            are copied to the output without any modification (spaces, punctuation,
            numbers, etc.).
        """
        letter_string = []
        for ordinal in input_string:
            if type(ordinal) == int:
                letter_string.append(chr(ordinal + ord('A')))
            else:
                letter_string.append(ordinal)
        return letter_string

    @staticmethod
    def _caesar_rotate(letter, shift_count):
        """ Shifts a single ordinal by amount specified in the key.
        """
        return (letter + shift_count) % 26

    @staticmethod
    def _caesar_shift_ordinals(original_ordinals, key):
        """ Shifts a list of ordinals by the amount specified in the key. Non-
            ordinals like spaces, punctuation, and numbers are copied to the output
            without any modification. Returns a list.
        """
        shifted_ordinals = []
        for ordinal in original_ordinals:
            if type(ordinal) == int:
                shifted_ordinals.append(Caesar._caesar_rotate(ordinal, key))
            else:
                shifted_ordinals.append(ordinal)
        return shifted_ordinals

    @staticmethod
    def calculate_frequencies(ciphertext):
        """ Calculates the frequency of each English letter in the text. Returns a
            list of 26 frequencies [A..Z].
        """
        frequencies = []
        ciphertext = ciphertext.lower()
        for ch in Caesar.english_alphabet:
            count = ciphertext.count(ch)
            frequencies.append(100.0 * count / len(ciphertext))
        return frequencies

    @staticmethod
    def score_frequencies(frequency_distribution):
        """ Scores a ciphertext distribution [A..Z] aginst the standard English
            frequency distribution. Input is a 26-item list of frequencies, whose
            sum should add up to 100. Returns a score value. Lower scores match
            English closer than higher scores.
        """
        # Score for each letter is the frequency difference between this letter
        # and english (e.g., 7.4% - 3.9%), squared.
        # Total score is sum of the individual scores.
        score = 0.0
        for i in range(26):
            frequency = frequency_distribution[i]
            standard = Caesar.english_frequencies[i]
            score += (frequency - standard) ** 2
        score = round(score, 1)
        return score

    @staticmethod
    def score_all_keys(ciphertext):
        """ Scores the ciphertext using all 26 possible keys and returns a list of
            all 26 scores. Returns a dictionary with each key being the encryption
            key and each value being the frequency score. Lowest score is most
            likely to belong to the correct Caesar Shift Cipher key.
        """
        # 1. Decrypt the ciphertext with one of the 26 possible keys
        # 2. Calculate the frequncy distribution of each letter_string
        # 3. Calculate the score for this frequency distribution
        frequency_list = {}
        for shift in range(26):
            possible_plaintext = Caesar.decrypt(ciphertext, shift)
            frequency_distribution = Caesar.calculate_frequencies(possible_plaintext)
            frequency_score = Caesar.score_frequencies(frequency_distribution)
            frequency_list[shift] = frequency_score
        return frequency_list
    # endregion
