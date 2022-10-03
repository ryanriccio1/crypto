# Author: Ryan Riccio
# Date: Sept 28th, 2022
# Program: Functions to make cryptanalysis of RailFence cipher easier
import string
import encryption_algorithms.cryptanalysis_wrapper as ca


class Playfair(object):
    @staticmethod
    def encrypt(plaintext, key):
        """
        Encrypt text using the Playfair cipher

        :param str plaintext: plaintext to encrypt.
        :param str key: key to use for grid.
        :return: ciphertext
        :rtype: str
        """
        # get grid and process plaintext
        grid = Playfair._create_playfair_grid(key)
        new_plaintext = ""
        for ch in plaintext:
            if ch.isalpha():
                if ch.lower() == 'j':
                    new_plaintext += 'i'
                else:
                    new_plaintext += ch
        plaintext = new_plaintext

        # get rid of double characters
        plaintext = Playfair._encode_playfair_digrams(plaintext)
        ciphertext = ""

        # take each digram and get its location
        for digram in plaintext:
            pos1 = Playfair._get_character_location(grid, digram[0])
            pos2 = Playfair._get_character_location(grid, digram[1])

            # check the grid based on the positions and add to ciphertext
            if pos1[1] == pos2[1]:
                ciphertext += Playfair._get_playfair_letter(grid, (pos1[0] + 1) % 5, pos1[1])
                ciphertext += Playfair._get_playfair_letter(grid, (pos2[0] + 1) % 5, pos2[1])
            elif pos1[0] == pos2[0]:
                ciphertext += Playfair._get_playfair_letter(grid, pos1[0], (pos1[1] + 1) % 5)
                ciphertext += Playfair._get_playfair_letter(grid, pos2[0], (pos2[1] + 1) % 5)
            else:
                d_col = pos1[1] - pos2[1]
                ciphertext += Playfair._get_playfair_letter(grid, pos1[0], pos1[1] - d_col)
                ciphertext += Playfair._get_playfair_letter(grid, pos2[0], pos2[1] + d_col)
        return ciphertext

    @staticmethod
    def decrypt(ciphertext, key):
        """
        Decrypt text using the Playfair cipher.

        :param ciphertext: ciphertext to decrypt.
        :param str key: key to use for the grid.
        :return: plaintext
        :rtype: str
        """
        # get grid and split ciphertext
        grid = Playfair._create_playfair_grid(key)
        new_ciphertext = ""
        for ch in ciphertext:
            if ch.isalpha():
                new_ciphertext += ch
        ciphertext = [new_ciphertext[idx:idx+2] for idx in range(0, len(new_ciphertext), 2)]
        plaintext = ""

        # go through each digram and check grid for decryption
        for digram in ciphertext:
            pos1 = Playfair._get_character_location(grid, digram[0])
            pos2 = Playfair._get_character_location(grid, digram[1])
            if pos1[1] == pos2[1]:
                plaintext += Playfair._get_playfair_letter(grid, (pos1[0] - 1) % 5, pos1[1])
                plaintext += Playfair._get_playfair_letter(grid, (pos2[0] - 1) % 5, pos2[1])
            elif pos1[0] == pos2[0]:
                plaintext += Playfair._get_playfair_letter(grid, pos1[0], (pos1[1] - 1) % 5)
                plaintext += Playfair._get_playfair_letter(grid, pos2[0], (pos2[1] - 1) % 5)
            else:
                d_col = pos1[1] - pos2[1]
                plaintext += Playfair._get_playfair_letter(grid, pos1[0], pos1[1] - d_col)
                plaintext += Playfair._get_playfair_letter(grid, pos2[0], pos2[1] + d_col)
        # remove 'Q's and join digrams
        return Playfair._decode_playfair_digrams(plaintext)

    @staticmethod
    def crack(ciphertext):
        """
        Crack a ciphertext using the Playfair cipher.

        :param ciphertext: ciphertext to try and crack.
        :return: best decrypted key
        :rtype: str
        """
        return ca.crack_playfair(ciphertext)

    # region Playfair Backend
    @staticmethod
    def print_cipher(key):
        """ Print cipher grid. """
        for idx in range(0, 25, 5):
            print(key[idx:idx+5])

    @staticmethod
    def _encode_playfair_digrams(text):
        """
        Encode digrams to be proper length for cipher.

        :param str text: text to encode
        :return: list of digrams
        :rtype: list[str]
        """
        # expand text into list
        split_text = [*text]
        idx = 0
        while idx < len(split_text):
            # if we are not at the last character and the two characters in the digram are equal
            if idx < len(split_text) - 1 and split_text[idx].lower() == split_text[idx + 1].lower():
                # insert 'Q'
                split_text = split_text[:idx + 1] + ['Q'] + split_text[idx + 1:]
            idx += 2
        # if digrams are not full, add 'Q'
        if len(split_text) % 2 != 0:
            split_text.append('Q')
        # split list into list of digrams
        return ["".join(split_text[idx:idx + 2]) for idx in range(0, len(split_text), 2)]

    @staticmethod
    def _decode_playfair_digrams(text) -> str:
        """
        Function to decode playfair digrams.

        :param text: text to modify
        :type text: str
        :return: str
        """
        # do not check first or last letter in string
        modified_text = text[0]
        for idx, ch in enumerate(text[1:-1], start=1):
            # check if 'Q' is surrounded by 2 of the same letters
            if text[idx - 1].lower() == text[idx + 1].lower():
                if ch.upper() != 'Q':
                    modified_text += ch
            else:
                modified_text += ch
        # add back the last letter
        if text[-1].upper() != 'Q':
            modified_text += text[-1]
        return modified_text

    @staticmethod
    def _create_playfair_grid(key):
        """ organize password to playfair grid. """
        new_key = ""
        # get only alphabetical letters
        for ch in key:
            if ch.isalpha():
                new_key += ch.upper()
        key = new_key
        # add all uppercase letters and remove J
        key += string.ascii_uppercase
        key.replace('J', '')

        # remove all duplicates
        key = "".join(dict.fromkeys(key.upper()))
        return key

    @staticmethod
    def _get_playfair_letter(key, row, col):
        """ find the char in specified position in a 5x5 grid. """
        # get letter at position
        return key[row * 5 + col]

    @staticmethod
    def _get_character_location(key, ch):
        """ find the position of a char in a 5x5 grid. """
        # get position given character
        idx = key.index(ch.upper())
        row = idx // 5
        col = idx % 5
        return row, col
    # endregion
