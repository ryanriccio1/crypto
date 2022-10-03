# Author: Ryan Riccio
# Date: Sept 17th, 2022
# Program: Functions to make cryptanalysis of RailFence cipher easier
import encryption_algorithms.cryptanalysis_wrapper as ca


class RailFence(object):
    @staticmethod
    def encrypt(plaintext, key=2, show_table=False) -> str:
        """
        Encrypt text using the Railfence cipher.

        :param plaintext: Text to encrypt
        :type plaintext: str
        :param key: Amount of rails to use.
        :type key: int
        :param show_table: Display the cipher itself.
        :type show_table: bool
        :return: str
        """
        # if it is not larger than 2, there is no real encryption
        if key < 2:
            raise ValueError("The key must be larger than 2")

        # convert our text to table, then turn the table to ciphertext
        table = RailFence._text_to_table(plaintext, key, encrypt=True)
        ciphertext = RailFence._table_to_text(table, encrypt=True, show_table=show_table)
        return f"'{ciphertext}'"

    @staticmethod
    def decrypt(ciphertext, key=2, show_table=False) -> str:
        """
        Decrypt text using the Railfence cipher.

        :param ciphertext: Text to decrypt
        :type ciphertext: str
        :param key: Amount of rails to use.
        :type key: int
        :param show_table: Display the cipher itself.
        :type show_table: bool
        :return: str
        """
        if key < 2:
            raise ValueError("The key must be larger than 2")
        table = RailFence._text_to_table(ciphertext, key, encrypt=False)
        plaintext = RailFence._table_to_text(table, encrypt=False, show_table=show_table)
        return plaintext

    @staticmethod
    def crack(text) -> tuple[str, int]:
        """
        Will return possible solutions to your text using RailFence.

        :param text: Text to try and crack.
        :type text: str
        :return: tuple[str, int]
        """

        output = {}
        num_tests = len(text)
        # check every possibility
        for key in range(2, num_tests):
            output[key] = ca.check_fitness(RailFence.decrypt(text, key).replace(" ", ''))

        # order them based on score
        sorted_dict = {k: v for k, v in sorted(output.items(), key=lambda item: item[1], reverse=True)}

        # return decrypted text and the key
        return RailFence.decrypt(text, list(sorted_dict.keys())[0]), list(sorted_dict.keys())[0]

    # region RailFence Backend
    @staticmethod
    def _text_to_table(text, key=2, encrypt=True):
        """ Convert text to railfence table. """
        # generate the table with empty data
        table = [['' for x in range(len(text))] for y in range(key)]

        # fill table
        if encrypt:
            table = RailFence._fill_rails(table, text, key)
        elif not encrypt:
            # fill table with '*' to mark where to decrypt letters from
            table = RailFence._fill_rails(table, '*' * len(text), key)
            text_idx = 0

            # replace '*' with the proper character
            for row in range(key):
                for col in range(len(text)):
                    if table[row][col] == '*' and text_idx < len(text):
                        table[row][col] = text[text_idx]
                        text_idx += 1

        return table

    @staticmethod
    def _table_to_text(table, encrypt, show_table=False):
        """ Convert railfence table back to text. """
        text = ""

        # whether we encrypt or decrypt, we need to calculate encryption table
        # loop through each row then column
        for idx in range(len(table)):
            for idy in range(len(table[0])):
                if show_table:
                    print(f"|{table[idx][idy]:^3}", end="")
                # if not empty, add table value to text
                if table[idx][idy] != "":
                    if encrypt:
                        text += table[idx][idy]
            if show_table:
                print()

        if not encrypt:
            # decryption reads the table differently
            # loop through each column then row
            for col in range(len(table[0])):
                for row in range(len(table)):
                    # if text exists, add to text
                    if table[row][col] != "":
                        text += table[row][col]

        return text

    @staticmethod
    def _fill_rails(table, text, key):
        """ fill rails in a table with a given key. """
        # fills rails with text
        direction = 'down'
        current_row, current_col = 0, 0

        # go through each character
        for num, ch in enumerate(text):
            table[current_row][current_col] = ch

            # depending on direction and position, change position

            # if we hit boundary row, change direction
            if current_row + 1 == key:
                direction = 'up'
            elif current_row == 0:
                direction = 'down'

            # change row based on direction
            if direction == 'down':
                current_row += 1
            else:
                current_row -= 1
            # always increment column
            current_col += 1
        return table
    # endregion
