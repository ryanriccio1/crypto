import argparse
import shutil
import glob
import re
import os

# make sure we have built the cryptanalysis module
if not os.path.exists('build'):
    os.system("python setup.py build_ext")
    for filename in glob.glob(os.path.join('build/lib*', '*.*')):
        print(filename)
        shutil.copy(filename, 'encryption_algorithms')

from encryption_algorithms import *


# associate input text with Enum
encryption_types = {
    'caesar': Algorithm.CAESAR,
    'enigma': Algorithm.ENIGMA,
    # 'otp': Algorithm.OTP, # no good way to take user input for otp
    'playfair': Algorithm.PLAYFAIR,
    'railfence': Algorithm.RAILFENCE,
    'substitution': Algorithm.SUBSTITUTION,
    'vigenere': Algorithm.VIGENERE
}


def main():
    parser = argparse.ArgumentParser(description="Tool to help encrypt and decrypt different kinds of encryption.")
    parser.add_argument('-m', '--mode', type=str, help="encrypt, decrypt, crack",
                        choices=['encrypt', 'decrypt', 'crack'], required=True, metavar="{MODE}")
    parser.add_argument('-a', '--algorithm', type=str, help="caesar, enigma, playfair, railfence, "
                                                            "substitution, vigenere",
                        choices=['caesar', 'enigma', 'playfair', 'railfence', 'substitution', 'vigenere'],
                        required=True, metavar="{ALGORITHM}")
    parser.add_argument('-k', '--key', type=str, help="key to use with encryption algorithm")
    parser.add_argument('-t', '--text', type=str, help="text to encrypt or decrypt")
    parser.add_argument('-f', '--file', type=argparse.FileType('r'), help='file to use instead of text')
    parser.add_argument('-o', '--output', type=argparse.FileType('w'),
                        help='file to write output to (will delete existing file)')
    group_railfence = parser.add_argument_group('Railfence')
    group_railfence.add_argument('-sT', '--show_table', action='store_true',
                                 help='will show table when railfence is algorithm')
    group_enigma = parser.add_argument_group('Enigma')
    group_enigma.add_argument('-r', '--rotors', type=str, help='3 rotors from 5: "I II III IV V" ex. "V IV III"')
    group_enigma.add_argument('-km', '--key_msg', type=str, help='message key (3 letters)')
    args = parser.parse_args()

    config = EnigmaConfig()
    args.algorithm = args.algorithm.lower()

    # make sure we have an output
    if args.file is None and args.text is None:
        parser.error("You must specify either a file or text! (-t, -f)")
    elif args.file is not None:
        # get file input
        args.text = args.file.read()

    # warn user about overwriting file
    if args.output is not None:
        print(f"WARNING: '{args.output.name}' has be overwritten!")
        while True:
            # input validation loop (N is default answer)
            keep_going = input("Keep going? (y/N): ")
            if keep_going.lower() == 'y':
                break
            elif keep_going.lower() == 'n' or keep_going == '':
                exit(0)
            else:
                print("That is not a valid input!")

    # python 3.10 case switching
    match args.algorithm:
        case 'caesar':
            try:
                # make sure key is int (unless we are cracking it)
                if args.mode != 'crack':
                    if args.key is None:
                        parser.error("You must specify a key! (-k)")
                    args.key = int(args.key)
                    if args.key < 1:
                        parser.error("The key must be greater than 1!")
            except ValueError:
                parser.error("That is not a valid key!")
        case 'enigma':
            # make sure we have all the necessary parts for enigma
            if args.mode == 'encrypt':
                if args.key_msg is None:
                    parser.error("You must specify a message key! (-km)")
                else:
                    # get rid of spaces
                    args.key_msg = args.key_msg.replace(" ", '')
                # make sure key is proper length
                if len(str(args.key_msg)) != 3:
                    parser.error("The message key must be 3 letters long!")
            if args.mode != 'crack':
                if args.key is None:
                    parser.error("You must specify a day key! (-k)")
                else:
                    args.key = args.key.replace(" ", '')
                if len(str(args.key)) != 3:
                    parser.error("The day key must be 3 letters long!")
                if args.rotors is None:
                    parser.error("You must specify the rotor config! (-r)")
                # make sure rotor input is correct
                regex = r"^([IV]{1,3}) ([IV]{1,3}) ([IV]{1,3})$"
                matches = re.match(regex, args.rotors)
                if matches is None:
                    parser.error("Invalid rotor config! (ex. 'I IV III')")
                # get rotor inputs
                r1, r2, r3 = matches.group(1), matches.group(2), matches.group(3)
                # we can only use 1 rotor each time
                if r1 == r2 or r2 == r3 or r1 == r3:
                    parser.error("Each rotor can only be used once!")

                # setup enigma simulation settings (only B reflector no rings)
                config.left_rotor = r1
                config.middle_rotor = r2
                config.right_rotor = r3
                config.left_start = args.key[0]
                config.middle_start = args.key[1]
                config.right_start = args.key[2]
                args.key = args.key_msg
        case 'playfair':
            pass
        case 'railfence':
            try:
                # make sure required args exist
                if args.mode != 'crack':
                    if args.key is None:
                        parser.error("You must specify a key! (-k)")
                    args.key = int(args.key)
                    # no sense in having a key of 1
                    if args.key < 2:
                        parser.error("The key must be greater than 2!")
            except ValueError:
                parser.error("That is not a valid key!")
        case 'substitution':
            pass
        case 'vigenere':
            pass

    # store output and display
    output = ""
    if args.mode == 'encrypt':
        output = encrypt(encryption_types[args.algorithm], args.text,
                         args.key, show_table=args.show_table, config=config)
    elif args.mode == 'decrypt':
        output = decrypt(encryption_types[args.algorithm], args.text,
                         args.key, show_table=args.show_table, config=config)
    elif args.mode == 'crack':
        output = crack(encryption_types[args.algorithm], args.text)

    if args.output is not None:
        args.output.write(output)
    else:
        print(output)


if __name__ == "__main__":
    main()
