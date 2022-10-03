import argparse
import math
import json


class NgramGenerator(object):
    def __init__(self, alphabet, infile, outfile, ngram_length):
        """ Setup ngram generator. """
        assert len(alphabet) <= 32, "Alphabet length must be <= 32 characters."
        assert ngram_length > 0
        current_chars = ""
        for char in alphabet:
            if char not in current_chars:
                current_chars += char.lower()

        self._alphabet = current_chars
        self._infile = infile
        self._outfile = outfile
        self._ngram_length = ngram_length

    def _file_processor(self):
        """ Iterator to process a file. """
        # yield only the characters in the alphabet
        alpha_dict = {v: k for k, v in enumerate(self._alphabet)}
        for line in self._infile:
            line = line.lower()
            for ch in line:
                test_val = alpha_dict.get(ch)
                if test_val is not None:
                    yield test_val

    def generate_ngrams(self):
        """ Write ngrams to json file. """
        # create an empty list
        ngrams = [0 for _ in range(32 ** self._ngram_length)]
        file = self._file_processor()

        # lop off the top few chars so we have some primed for the main loop
        ngram_idx = file.__next__()
        if self._ngram_length > 2:
            for idx in range(self._ngram_length - 2):
                ngram_idx = (ngram_idx << 5) + file.__next__()

        # generate bitmask based on legnth of ngrams
        bitmask = 0
        for idx in range((self._ngram_length - 1) * 5):
            bitmask = (bitmask << 1) + 1

        print('Counting ngrams...')
        for char_idx in file:
            # the index will be the 5bit representation (max 32 chars) of
            # our char that the file processor has given us
            ngram_idx = ((ngram_idx & bitmask) << 5) + char_idx
            # print(bin(ngram_idx)[2:].zfill(self._ngram_length*5))
            # for every index, count towards total
            ngrams[ngram_idx] += 1

        print('Determining Frequency...')
        # get total number of ngrams
        ngram_count = sum(ngrams)
        # the minimum cant be more than the count
        ngram_min = ngram_count
        for char_freq in ngrams:
            if char_freq:
                # get the frequency of the lowest ngram
                ngram_min = min(ngram_min, char_freq)

        # offset so we do not get divide by 0 and so even outliers will be given
        # 1/10 of the minimum score (text that is all outliers, but still possibly english
        # will get a minimal, but not 0 score)
        offset = math.log(ngram_min / 10 / ngram_count)

        norm = 0
        print('Normalizing Values...')
        for idx, char_freq in enumerate(ngrams):
            # if the frequency exists
            if char_freq:
                # get the percent frequency
                percent_frequency = char_freq / ngram_count
                # normalize and offset
                value = math.log(percent_frequency) - offset
                ngrams[idx] = value  # reassign ngram score to normalized frequency
                # keep track of how much we normalized (basically variation)
                norm += percent_frequency * value

        print('Rounding values...')
        for idx, val in enumerate(ngrams):
            # fully normalize and multiply * 1000 (values closer to 1000 are better)
            # this way we can divide by 10 later to get range 0-100 for scores without
            # storing floats. scores can be greater than 100, but not easily
            ngrams[idx] = round(ngrams[idx] / norm * 1000)

        print('Writing to file...')
        json.dump(
            {
                "alphabet": self._alphabet,
                "num_ngrams": ngram_count,
                "max_fitness": max(ngrams),
                "average_fitness": sum(ngrams) / (len(self._alphabet) ** self._ngram_length),
                "ngram_length": self._ngram_length,
                "ngrams": ngrams,
            },
            self._outfile,
            indent=0,
        )
        print(f'"alphabet": "{self._alphabet}",')
        print(f'"num_ngrams": {ngram_count},')
        print(f'"max_fitness": {max(ngrams)},')
        print(f'"average_fitness": {sum(ngrams) / (len(self._alphabet) ** self._ngram_length)},')
        print("Done!")


def main():
    parser = argparse.ArgumentParser(description="Generate list of ngrams from file.")
    parser.add_argument('alphabet', type=str,
                        help="string of characters to use for ngram frequency generation (max 32)")
    parser.add_argument('input', type=argparse.FileType('r', encoding="utf-8"),
                        help="file to generate frequencies from")
    parser.add_argument('output', type=argparse.FileType('w'), help="file to write output to")
    parser.add_argument('length', type=int, help="length of the ngram")

    args = parser.parse_args()

    if len(args.alphabet) > 32:
        parser.error("The length of the alphabet must be <= 32 characters.")
    if args.length < 1:
        parser.error("The ngram length must be <= 1.")

    generator = NgramGenerator(args.alphabet, args.input, args.output, args.length)
    generator.generate_ngrams()


if __name__ == '__main__':
    main()
