# Author: Ryan Riccio
# Date: Sept 30th, 2022
# Program: Wrapper for C++ cryptanalysis library
import encryption_algorithms.cryptanalysis as ca


def check_fitness(text):
    """
    Give text a score based on its similarity to English.

    :param str text: text to score.
    :return: fitness of text (values closer to 100 are more fit).
    :rtype: float
    """
    score = ca.ScoreText("ngrams/quadgrams.json")
    return score.c_score(text)


def crack_playfair(ciphertext):
    """
    Crack playfair.

    :param str ciphertext: ciphertext to decrypt
    :return: decrypted ciphertext
    :rtype: str
    """
    cracker = ca.PlayfairCrack("ngrams/playfair/quadgrams.json")
    return ca.mt_c_crack(cracker, ciphertext, iterations=3000, temp=30, step=0.2, fudge=0.75, threshold=95)


def crack_substitution(ciphertext):
    """
    Crack Substitution.

    :param str ciphertext: ciphertext to decrypt.
    :return: decrypted ciphertext
    :rtype: str
    """
    cracker = ca.SubstitutionCrack("ngrams/quadgrams.json")
    return cracker.c_crack(ciphertext)
