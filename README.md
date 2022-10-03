# Crypto.py

This is a commandline tool that allows for cryptographic analysis of a few types of ciphers and encryption.

Running is simple:
`python crypto.py -h`

This will build the C++ extensions as well as give you info about commandline usage.

```
usage: crypto.py [-h] -m {MODE} -a {ALGORITHM} [-k KEY] [-t TEXT] [-f FILE] [-o OUTPUT] [-sT] [-r ROTORS]
                 [-km KEY_MSG]

Tool to help encrypt and decrypt different kinds of encryption.

options:
  -h, --help            show this help message and exit
  -m {MODE}, --mode {MODE}
                        encrypt, decrypt, crack
  -a {ALGORITHM}, --algorithm {ALGORITHM}
                        caesar, enigma, playfair, railfence, substitution, vigenere
  -k KEY, --key KEY     key to use with encryption algorithm
  -t TEXT, --text TEXT  text to encrypt or decrypt
  -f FILE, --file FILE  file to use instead of text
  -o OUTPUT, --output OUTPUT
                        file to write output to (will delete existing file)

Railfence:
  -sT, --show_table     will show table when railfence is algorithm

Enigma:
  -r ROTORS, --rotors ROTORS
                        3 rotors from 5: "I II III IV V" ex. "V IV III"
  -km KEY_MSG, --key_msg KEY_MSG
                        message key (3 letters)
```
