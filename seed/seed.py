from hashlib import sha512
import hmac
import unicodedata
from pbkdf2 import PBKDF2

def get_wordlist(filepath):
    """
    Get list of words from the file. Each line is interpreted as a word (except the possibly empty last line).
    """
    with open(filepath, "r") as f:
        wordlist = f.read().split("\n")
        if wordlist[-1] == "":
            wordlist.pop(-1)

        if len(wordlist) != 2048:
            raise ValueError("the filepath contains {} lines interpreted as words; "
                             "it should contain 2048 words".format(len(wordlist)))

        return wordlist

def generate_seed(mnemonic, passphrase='', filepath='../wordlists/english.txt'):
    """
    Get the seed from a mnemonic
    :param mnemonic: mnemonic as a string
    :param passphrase: passphrase as a string
    :param filepath: path to the used wordlist
    :return: seed as a hex string
    """

    wordlist = get_wordlist(filepath)
    splited_mnemonic = mnemonic.split()
    for i in range(0,len(splited_mnemonic)):
        if(splited_mnemonic[i] not in wordlist):
            raise ValueError("the given mnemonic contains illegal(s) word(s)")

    nfkd_mnemonic = bytes(unicodedata.normalize('NFKD', mnemonic), encoding='utf-8')
    concat = 'mnemonic' + passphrase
    nfkd_salt = bytes(unicodedata.normalize('NFKD', concat), encoding='utf-8')
    seed = PBKDF2(nfkd_mnemonic, nfkd_salt, 2048, macmodule=hmac, digestmodule=sha512).read(64).hex()

    return seed
