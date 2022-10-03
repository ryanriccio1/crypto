# Authors: Joshua Tallman, Ryan Riccio
# Date: Sept 17th, 2022
# Program: For encrypting and decrypting text messages using an Enigma simulator.

# region Enigma Backend
class EnigmaConfig(object):
    def __init__(self, reflector="B",
                 left_rotor="III", middle_rotor="II", right_rotor="I",
                 left_start="A", middle_start="A", right_start="A",
                 left_ring="A", middle_ring="A", right_ring="A"):
        """
        Stores information about the setup of the Enigma Machine.

        :param reflector: Must be 'B' or 'C'
        :type reflector:str
        :param left_rotor: Must be 'I', 'II', 'III', 'IV', 'V'
        :type left_rotor: str
        :param middle_rotor: Must be 'I', 'II', 'III', 'IV', 'V'
        :type middle_rotor: str
        :param right_rotor: Must be 'I', 'II', 'III', 'IV', 'V'
        :type right_rotor: str
        :param left_start: Must be capital alphabetical character.
        :type left_start: str
        :param middle_start: Must be capital alphabetical character.
        :type middle_start: str
        :param right_start: Must be capital alphabetical character.
        :type right_start: str
        :param left_ring: Must be capital alphabetical character.
        :type left_ring: str
        :param middle_ring: Must be capital alphabetical character.
        :type middle_ring: str
        :param right_ring: Must be capital alphabetical character.
        :type right_ring: str
        """
        self.rotors = ['I', 'II', 'III', 'IV', 'V']

        self.reflector = reflector
        self.left_rotor = left_rotor
        self.middle_rotor = middle_rotor
        self.right_rotor = right_rotor
        self.left_start = left_start
        self.middle_start = middle_start
        self.right_start = right_start
        self.left_ring = left_ring
        self.middle_ring = middle_ring
        self.right_ring = right_ring

        if self.left_rotor == self.middle_rotor or self.left_rotor == self.right_rotor \
                or self.middle_rotor == self.right_rotor:
            raise ValueError("All rotors must be unique")

    @property
    def reflector(self) -> str:
        return self._reflector

    @property
    def left_rotor(self) -> str:
        return self._left_rotor

    @property
    def middle_rotor(self) -> str:
        return self._middle_rotor

    @property
    def right_rotor(self) -> str:
        return self._right_rotor

    @property
    def left_start(self) -> str:
        return self._left_start

    @property
    def middle_start(self) -> str:
        return self._middle_start

    @property
    def right_start(self) -> str:
        return self._right_start

    @property
    def left_ring(self) -> str:
        return self._left_ring

    @property
    def middle_ring(self) -> str:
        return self._middle_ring

    @property
    def right_ring(self) -> str:
        return self._right_ring

    @reflector.setter
    def reflector(self, value: str):
        """
        Value for Enigma reflector.

        :param value: Must be 'B' or 'C'
        :return: None
        """
        if value.upper() == 'B' or value.upper() == 'C':
            self._reflector = value.upper()
        else:
            raise ValueError("Reflector must be 'B' or 'C'.")

    @left_rotor.setter
    def left_rotor(self, value: str):
        """
        Value for Enigma rotor.

        :param value: Must be 'I', 'II', 'III', 'IV', 'V'
        :return: None
        """
        if value.upper() in self.rotors:
            self._left_rotor = value.upper()
        else:
            raise ValueError("That is not a valid rotor (I, II, III, IV, V).")

    @middle_rotor.setter
    def middle_rotor(self, value: str):
        """
        Value for Enigma rotor.

        :param value: Must be 'I', 'II', 'III', 'IV', 'V'
        :return: None
        """
        if value.upper() in self.rotors:
            self._middle_rotor = value.upper()
        else:
            raise ValueError("That is not a valid rotor (I, II, III, IV, V).")

    @right_rotor.setter
    def right_rotor(self, value: str):
        """
        Value for Enigma rotor.

        :param value: Must be 'I', 'II', 'III', 'IV', 'V'
        :return: None
        """
        if value.upper() in self.rotors:
            self._right_rotor = value.upper()
        else:
            raise ValueError("That is not a valid rotor (I, II, III, IV, V).")

    @left_start.setter
    def left_start(self, value: str):
        """
        Starting position for Enigma rotor.

        :param value: Must be single letter
        :return: None
        """
        if value.isalpha() and len(value) == 1:
            self._left_start = value.upper()
        else:
            raise ValueError("Starting character must be a single letter!")

    @middle_start.setter
    def middle_start(self, value: str):
        """
        Starting position for Enigma rotor.

        :param value: Must be single letter
        :return: None
        """
        if value.isalpha() and len(value) == 1:
            self._middle_start = value.upper()
        else:
            raise ValueError("Starting character must be a single letter!")

    @right_start.setter
    def right_start(self, value: str):
        """
        Starting position for Enigma rotor.

        :param value: Must be single letter
        :return: None
        """
        if value.isalpha() and len(value) == 1:
            self._right_start = value.upper()
        else:
            raise ValueError("Starting character must be a single letter!")

    @left_ring.setter
    def left_ring(self, value: str):
        """
        Offset position for Enigma rotor.

        :param value: Must be single letter
        :return: None
        """
        if value.isalpha() and len(value) == 1:
            self._left_ring = value.upper()
        else:
            raise ValueError("Ring character must be a single letter!")

    @middle_ring.setter
    def middle_ring(self, value: str):
        """
        Offset position for Enigma rotor.

        :param value: Must be single letter
        :return: None
        """
        if value.isalpha() and len(value) == 1:
            self._middle_ring = value.upper()
        else:
            raise ValueError("Ring character must be a single letter!")

    @right_ring.setter
    def right_ring(self, value: str):
        """
        Offset position for Enigma rotor.

        :param value: Must be single letter
        :return: None
        """
        if value.isalpha() and len(value) == 1:
            self._right_ring = value.upper()
        else:
            raise ValueError("Ring character must be a single letter!")


# physical simulator of enigma M3
class _m3:
    """ A class that implements the German M3 Enigma that was used by the Army
        and Navy in WWII. It has three rotors, a reflector, and a plugboard.
        There is another part that plays a very minor role in encryption, the
        rings, but these are not implemented for simplicity. It would be easy to
        add them by simply adjusting the initial counter values for each rotor.
    """

    def __init__(self, ec: EnigmaConfig, plugboard={}):
        """ Initializes the M3 Enigma machine by choosing which reflector and
            rotors to use and their initial settings (the letter showing in the
            top of the Enigma box). It also sets plugboard. If rings were added
            they would be set here.
        """
        self.reset(ec)

    def reset(self, ec: EnigmaConfig, plugboard=[]):
        """ Initializes the M3 Enigma machine by choosing which reflector and
            rotors to use and their initial settings (the letter showing in the
            top of the Enigma box). It also sets plugboard. If rings were added
            they would be set here.
        """
        self._reflector = _mechanical.reflector[ec.reflector.upper()]
        self._L_rotor = _mechanical.rotor[ec.left_rotor.upper()]
        self._M_rotor = _mechanical.rotor[ec.middle_rotor.upper()]
        self._R_rotor = _mechanical.rotor[ec.right_rotor.upper()]
        self._L_rotor["counter"] = (self._letter_to_ordinal(ec.left_start) - self._letter_to_ordinal(ec.left_ring)) % 26
        self._M_rotor["counter"] = (self._letter_to_ordinal(ec.middle_start) - self._letter_to_ordinal(
            ec.middle_ring)) % 26
        self._R_rotor["counter"] = (self._letter_to_ordinal(ec.right_start) - self._letter_to_ordinal(
            ec.right_ring)) % 26
        self._plugboard = {i: i for i in range(26)}
        for plug in plugboard:
            k1 = self._letter_to_ordinal(plug[0])
            k2 = self._letter_to_ordinal(plug[-1])
            self._plugboard[k1] = k2
            self._plugboard[k2] = k1

    def keypress(self, letter, debug=False):
        """ Encrypts a single key pressed on the keyboard. Returns the self._letter_to_ordinal
            that is lit on the lampboard.
        """
        # If the user entered punctuation, a number, or other symbol, just pass
        # it through without using the Enigma.
        if not isinstance(letter, str) or \
                len(letter) > 1 or \
                not letter.isalpha():
            return letter

        # Convert from a letter to a number
        # 1) Step the rotors forward
        # 2) Entry through the plugboard
        # 3) Entry through the three rotors
        # 4) Bounced back through the reflectors
        # 5) Return through the three rotors
        # 6) Return through the plugboard
        # Convert back from a number to a letter
        ch0 = self._letter_to_ordinal(letter)
        self._step()
        ch1 = self._plugboard[ch0]
        ch2 = self._rotor(ch1, self._R_rotor, "forward")
        ch3 = self._rotor(ch2, self._M_rotor, "forward")
        ch4 = self._rotor(ch3, self._L_rotor, "forward")
        ch5 = self._bounce_back(ch4, self._reflector)
        ch6 = self._rotor(ch5, self._L_rotor, "reverse")
        ch7 = self._rotor(ch6, self._M_rotor, "reverse")
        ch8 = self._rotor(ch7, self._R_rotor, "reverse")
        ch9 = self._plugboard[ch8]
        if debug:
            L_letter = self._ordinal_to_letter(self._L_rotor["counter"])
            M_letter = self._ordinal_to_letter(self._M_rotor["counter"])
            R_letter = self._ordinal_to_letter(self._R_rotor["counter"])
            m = "{0}{1}{2} {3} : {4} -> {5} -> {6} -> {7} | {8} -> {9} -> {10} -> {11} : {12}"
            print(m.format(L_letter, M_letter, R_letter,
                           self._ordinal_to_letter(ch0), self._ordinal_to_letter(ch1),
                           self._ordinal_to_letter(ch2), self._ordinal_to_letter(ch3),
                           self._ordinal_to_letter(ch4), self._ordinal_to_letter(ch5),
                           self._ordinal_to_letter(ch6), self._ordinal_to_letter(ch7),
                           self._ordinal_to_letter(ch8), self._ordinal_to_letter(ch9)))
        return self._ordinal_to_letter(ch9)

    # region M3 Backend
    def _step(self):
        """ Steps the rotors forward for a single keypress.
        """
        if self._M_rotor["counter"] == self._M_rotor["pushpeg"]:
            self._L_rotor["counter"] = (self._L_rotor["counter"] + 1) % 26
            self._M_rotor["counter"] = (self._M_rotor["counter"] + 1) % 26
        if self._R_rotor["counter"] == self._R_rotor["pushpeg"]:
            self._M_rotor["counter"] = (self._M_rotor["counter"] + 1) % 26
        self._R_rotor["counter"] = (self._R_rotor["counter"] + 1) % 26

    def _rotor(self, enter_wire, rotor, direction="forward"):
        """ Encrypts a signal passing through a single rotor.
        """
        rotor_indx = (enter_wire + rotor["counter"]) % 26
        leave_wire = (enter_wire + rotor[direction][rotor_indx]) % 26
        return leave_wire

    def _bounce_back(self, enter_wire, reflector):
        """ Encrypts a signal passing through the reflector.
        """
        leave_wire = (enter_wire + reflector[enter_wire]) % 26
        return leave_wire

    def _letter_to_ordinal(self, letter):
        if letter.isalpha():
            if letter.islower():
                return ord(letter) - ord('a')
            else:
                return ord(letter) - ord('A')
        else:
            return letter

    def _ordinal_to_letter(self, ordinal):
        if type(ordinal) == int:
            return chr(ordinal + ord('A'))
        else:
            return ordinal
    # endregion


class _mechanical:
    """ Technical specifications of the M3 Enigma mechnical parts based on the
        website http://users.telenet.be/d.rijmenants/en/enigmatech.htm
    """
    rotor = \
        {
            "I": {
                "forward": [4, 9, 10, 2, 7, 1, -3, 9, 13, -10, 3, 8, 2, 9, 10, -8, 7, 3, 0, -4, 6, 13, 5, -6, 4, 10],
                "reverse": [-6, -5, -4, 3, -4, -2, -1, 8, -13, -10, -9, -7, -10, -3, -2, 4, -9, 6, 0, -8, -3, -13, -9,
                            -7, -10, 10],
                "counter": 0,
                "pushpeg": 16
            },
            "II": {
                "forward": [0, 8, 1, 7, -12, 3, 11, 13, -11, -8, 1, -4, 10, 6, -2, 13, 0, -11, 7, -6, -5, 3, 9, -2, -10,
                            5],
                "reverse": [0, 8, -13, -1, -5, -9, 11, 4, -3, -8, -7, -1, 2, 6, 10, 5, 0, -11, 12, -6, -13, 2, -10, 11,
                            -3, -7],
                "counter": 0,
                "pushpeg": 4
            },
            "III": {
                "forward": [1, 2, 3, 4, 5, 6, -4, 8, 9, 10, 13, 10, 13, 0, 10, -11, -8, 5, -12, 7, -10, -9, -2, -5, -8,
                            -11],
                "reverse": [-7, -1, 4, -2, 11, -3, 12, -4, 8, -5, 10, -6, 9, 0, 11, -8, 8, -9, 5, -10, 2, -10, -5, -13,
                            -10, -13],
                "counter": 0,
                "pushpeg": 21
            },
            "IV": {
                "forward": [4, -9, 12, -8, 11, -6, 3, -7, -10, 7, 10, -3, 5, -6, 9, -4, -3, -12, 1, 13, -10, 8, 6, -11,
                            -2, 2],
                "reverse": [7, -2, -6, -8, -4, 12, -13, 6, 3, -3, 10, 4, 11, 3, -12, -11, -7, -5, 9, -1, -10, 8, 2, -9,
                            10, 6],
                "counter": 0,
                "pushpeg": 9
            },
            "V": {
                "forward": [-5, -2, -1, -12, 2, 3, 13, -9, 12, 6, 8, -8, 1, -6, -3, 8, 10, 5, -6, -10, -4, -7, 9, 7, 4,
                            11],
                "reverse": [-10, 1, -4, 8, -7, -9, -2, 6, -3, 10, -11, 3, 6, -1, 7, -6, 4, 12, -8, -13, -12, 5, -5, -8,
                            9, 2],
                "counter": 0,
                "pushpeg": 25
            }
        }
    reflector = \
        {
            "B": [-2, -10, -8, 4, 12, 13, 5, -4, 7, -12, 3, -5, 2, -3, -2, -7, -12, 10, -13, 6, 8, 1, -1, 12, 2, -6],
            "C": [5, -6, 13, 6, 4, -5, 8, -9, -4, -6, 7, -12, 11, 9, -8, -13, 3, -7, 2, -3, -2, 6, -9, -11, 9, 12]
        }
# endregion


class Enigma(object):
    @staticmethod
    def encrypt(plaintext, msg_key, ec: EnigmaConfig) -> str:
        """
        Will encrypt text using an Enigma simulator.

        :param plaintext:
        :type plaintext:
        :param msg_key:
        :type msg_key:
        :param ec: Configuration of the machine
        :type ec: EnigmaConfig
        :return: str
        """
        # make sure the day key is the correct length
        if len(msg_key) == 3:
            # encrypt the day key
            my_enigma = _m3(ec)
            ciphertext = ""
            for idx in range(6):
                ciphertext += my_enigma.keypress(msg_key[idx % 3])
            ciphertext += " "

            # switch rotors to day key
            ec.left_start, ec.middle_start, ec.right_start = msg_key[0], msg_key[1], msg_key[2]
            my_enigma.reset(ec)

            # encrypt plaintext
            for ch in plaintext:
                ciphertext += my_enigma.keypress(ch)
            return ciphertext
        else:
            raise ValueError("Day Key must be 3 characters long!")

    @staticmethod
    def decrypt(ciphertext, ec: EnigmaConfig) -> tuple[str, str]:
        """
        Decrypt text given Enigma Machine and day key at start of message.

        :param ciphertext: Text to decrypt.
        :type ciphertext: str
        :param ec: Configuration of the Enigma Machine.
        :type ec: EnigmaConfig
        :return: tuple with the plaintext and message key.
        """
        my_enigma = _m3(ec)

        # separate day key and ciphertext
        first_six = ciphertext[:6]  # first 6 letters
        ciphertext = ciphertext[6:].strip()  # real ciphertext message

        # decrypt the message key
        msg_key = [my_enigma.keypress(ch) for ch in first_six]

        # check for valid message key and decrypt the message
        if msg_key[0] == msg_key[3] and msg_key[1] == msg_key[4] and msg_key[2] == msg_key[5]:
            plaintext = ""
            ec.left_start, ec.middle_start, ec.right_start = msg_key[0], msg_key[1], msg_key[2]
            my_enigma.reset(ec)
            for ch in ciphertext:
                plaintext += my_enigma.keypress(ch)
            return plaintext, f"{msg_key[0]}{msg_key[1]}{msg_key[2]}"
        else:
            raise ValueError("That is not a valid daily key!")

    @staticmethod
    def crack(message) -> tuple[str, [str, str, str, str, str]]:
        """
        Use frequency analysis to estimate the most likely solution to an enigma ciphertext
        Brute force assuming no rings and no plugboard setup. Assuming the first 6 characters
        are the msg key repeated twice.

        :param message: Text to be cracked
        :type message: str
        :return tuple with the plaintext and the settings
        """
        import psutil
        import time
        import multiprocessing
        from itertools import permutations

        # get logical number of cores
        num_cpu = psutil.cpu_count(logical=True)

        # calculate how many CPUs we can actually use and how to split them evenly
        if num_cpu > 1:
            num_cpu -= 2
            while True:
                if 60 % num_cpu == 0:
                    num_jobs = num_cpu
                    break
                else:
                    num_cpu -= 1
        else:
            num_jobs = 1

        rotors = ["I", "II", "III", "IV", "V"]
        total_combinations = []

        # start the timer
        start = time.time()

        # split every combination of rotors between the CPUs
        for rotor_l, rotor_m, rotor_r in permutations(rotors, 3):
            total_combinations.append([rotor_l, rotor_m, rotor_r])

        num_splits = 60 // num_jobs
        split_jobs = [total_combinations[idx:idx + num_splits] for idx in range(0, len(total_combinations), num_splits)]

        print(f"Starting up {num_jobs} jobs to crack enigma.")

        # start the jobs
        manager = multiprocessing.Manager()
        shared_dict = manager.dict()
        processes = []
        for idx in range(num_jobs):
            p = multiprocessing.Process(target=Enigma._crack_job, args=(message, split_jobs[idx], shared_dict))
            processes.append(p)
            p.start()

        # wait for all jobs to finish
        for current_process in processes:
            current_process.join()
        end = time.time()   # end time
        print(f"Cracked enigma in {end - start:.2f} sec.")

        # sort results and store the settings
        sorted_dict = {k: v for k, v in sorted(shared_dict.items(), key=lambda item: item[0])}
        settings = list(sorted_dict.values())[0]

        # decrypt using the settings
        ec = EnigmaConfig(left_rotor=settings[0], middle_rotor=settings[1], right_rotor=settings[2],
                          left_start=settings[4][0], middle_start=settings[4][1], right_start=settings[4][2])
        plaintext = Enigma.decrypt(message, ec)[0]
        return plaintext, settings

    # region Crack Worker
    @staticmethod
    def _crack_job(message, rotor_list, shared_dict):
        """
        Worker process to find the settings of an Enigma Machine
        """
        from itertools import product
        from encryption_algorithms.caesar import Caesar

        key_info = {}

        # go through every combination of given rotors and positions
        for rotors in rotor_list:
            scramblers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            for start_l, start_m, start_r in product(scramblers, repeat=3):
                # test if this is a valid setup, then decrypt and perform frequency analysis if valid
                config = EnigmaConfig("B", rotors[0], rotors[1], rotors[2], start_l, start_m, start_r)
                try:
                    decrypted = Enigma.decrypt(message, config)
                    settings = (rotors[0], rotors[1], rotors[2], decrypted[1],
                                f"{start_l}{start_m}{start_r}")

                    # use frequency analysis to see if this is a good decryption
                    frequency_distribution = Caesar.calculate_frequencies(decrypted[0])
                    key_info[settings] = Caesar.score_frequencies(frequency_distribution)
                except ValueError:  # if decryption does not work, start over
                    continue

        # sort answers and return our best work
        scored_dict = {k: v for k, v in sorted(key_info.items(), key=lambda item: item[1])}
        best_config = list(scored_dict.keys())[0]
        shared_dict[scored_dict[best_config]] = best_config
    # endregion
