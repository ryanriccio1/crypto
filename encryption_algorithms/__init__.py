from encryption_algorithms.caesar import *
from encryption_algorithms.enigma import *
from encryption_algorithms.otp import *
from encryption_algorithms.playfair import *
from encryption_algorithms.railfence import *
from encryption_algorithms.substitution import *
from encryption_algorithms.vigenere import *
import encryption_algorithms.cryptanalysis_wrapper
from enum import Enum


# Enum to store different types of algorithms
class Algorithm(Enum):
    CAESAR = 1
    ENIGMA = 2
    OTP = 3
    PLAYFAIR = 4
    RAILFENCE = 5
    SUBSTITUTION = 6
    VIGENERE = 7


# make only 1 version of each function (encrypt, decrypt, crack, and select mode based on algorithm)
def encrypt(algorithm, plaintext, key, config=None, show_table=False):
    match algorithm:
        case Algorithm.CAESAR:
            return Caesar.encrypt(plaintext, key)
        case Algorithm.ENIGMA:
            return Enigma.encrypt(plaintext, key, config)
        case Algorithm.OTP:
            return OTP.crypt(plaintext, key)
        case Algorithm.PLAYFAIR:
            return Playfair.encrypt(plaintext, key)
        case Algorithm.RAILFENCE:
            return RailFence.encrypt(plaintext, key, show_table)
        case Algorithm.SUBSTITUTION:
            key = Substitution.generate_key_from_password(key)
            return Substitution.encrypt(plaintext, key)
        case Algorithm.VIGENERE:
            return Vigenere.encrypt(plaintext, key)


def decrypt(algorithm, ciphertext, key, config=None, show_table=False):
    match algorithm:
        case Algorithm.CAESAR:
            return Caesar.decrypt(ciphertext, key)
        case Algorithm.ENIGMA:
            return Enigma.decrypt(ciphertext, config)
        case Algorithm.OTP:
            return OTP.crypt(ciphertext, key)
        case Algorithm.PLAYFAIR:
            return Playfair.decrypt(ciphertext, key)
        case Algorithm.RAILFENCE:
            return RailFence.decrypt(ciphertext, key, show_table)
        case Algorithm.SUBSTITUTION:
            key = Substitution.generate_key_from_password(key)
            return Substitution.decrypt(ciphertext, key)
        case Algorithm.VIGENERE:
            return Vigenere.decrypt(ciphertext, key)


def crack(algorithm, ciphertext):
    match algorithm:
        case Algorithm.CAESAR:
            return Caesar.crack(ciphertext)
        case Algorithm.ENIGMA:
            return Enigma.crack(ciphertext)
        case Algorithm.OTP:
            return OTP.crack(ciphertext)
        case Algorithm.PLAYFAIR:
            return Playfair.crack(ciphertext)
        case Algorithm.RAILFENCE:
            return RailFence.crack(ciphertext)
        case Algorithm.SUBSTITUTION:
            return Substitution.crack(ciphertext)
        case Algorithm.VIGENERE:
            return Vigenere.crack(ciphertext)
