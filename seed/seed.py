from hashlib import sha512
import hmac
import unicodedata
from pbkdf2 import PBKDF2

def generate_seed(mnemonic, passphrase='TREZOR'):
    """
    Get the seed from a mnemonic
    :param mnemonic: mnemonic as a string
    :param passphrase: passphrase as a string
    :return: seed as a hex string
    """
    nfkd_mnemonic = bytes(unicodedata.normalize('NFKD', mnemonic), encoding='utf-8')

    concat = 'mnemonic' + passphrase
    nfkd_salt = bytes(unicodedata.normalize('NFKD', concat), encoding='utf-8')

    seed = PBKDF2(nfkd_mnemonic, nfkd_salt, 2048, macmodule=hmac, digestmodule=sha512).read(64).hex()

    return seed
