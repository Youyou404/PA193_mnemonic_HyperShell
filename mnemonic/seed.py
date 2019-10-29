from hashlib import sha512
import hmac
import unicodedata
from pbkdf2 import PBKDF2
from mnemonic.util import get_wordlist


def generate_seed(mnemonic, passphrase='', filepath='../wordlists/english.txt'):
    """
    Get the seed from a mnemonic
    :param mnemonic: mnemonic as a string
    :param passphrase: passphrase as a string
    :param filepath: path to the used wordlist
    :return: seed as a hex string
    """

    wordlist = get_wordlist(filepath)
    split_mnemonic = mnemonic.split()
    for member in split_mnemonic:
        if member not in wordlist:
            raise ValueError("the given mnemonic contains illegal(s) word(s)")

    nfkd_mnemonic = bytes(unicodedata.normalize('NFKD', mnemonic), encoding='utf-8')
    concat = 'mnemonic' + passphrase
    nfkd_salt = bytes(unicodedata.normalize('NFKD', concat), encoding='utf-8')
    seed = PBKDF2(nfkd_mnemonic, nfkd_salt, 2048, macmodule=hmac, digestmodule=sha512).read(64).hex()

    return seed
