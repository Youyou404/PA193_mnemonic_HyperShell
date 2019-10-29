import os
from hashlib import sha256
from mnemonic.util import get_wordlist

POSSIBLE_ENT_VALUES = [128, 160, 192, 224, 256]


def generate_entropy_bytes(ent):
    """
    Generate ent cryptographically secure bytes.

    :param ent: entropy length; type int; possible values from POSSIBLE_ENT_VALUES
    :return: bytes object of entropy
    """
    if type(ent) is not int:
        raise ValueError('ent (entropy length) has to be int; the given type was {}'.format(type(ent)))
    if ent not in POSSIBLE_ENT_VALUES:
        raise ValueError(
            'ent (entropy length) has to be in {}; the given values was {}'.format(POSSIBLE_ENT_VALUES, ent))

    entropy_bytes = os.urandom(ent // 8)

    assert len(entropy_bytes) == ent // 8
    return entropy_bytes


def is_bit_string(string):
    """
    Check whether the given values is a string containing only '1's and '0's.
    """
    if type(string) is not str:
        return False
    for x in string:
        if x not in ['0', '1']:
            return False
    return True


def bytes_to_bits(value_bytes):
    """
    Convert bytes to bit string.
    """
    if type(value_bytes) is not bytes:
        raise ValueError('value_bytes has to be bytes object; the given type was {}'.format(type(value_bytes)))

    value_bits = ''.join(format(x, '08b') for x in value_bytes)

    assert is_bit_string(value_bits)
    assert len(value_bits) == len(value_bytes) * 8
    return value_bits


def get_checksum(entropy_bytes):
    """
    Get checksum bit string for the entropy bytes.
    """
    if type(entropy_bytes) is not bytes:
        raise ValueError('entropy_bytes has to be bytes object; the given type was {}'.format(type(entropy_bytes)))
    if len(entropy_bytes) * 8 not in POSSIBLE_ENT_VALUES:
        raise ValueError(
            'eight multiple of entropy_bytes length has to be in {}; '
            'the eight multiple of length of the given values was {}'.format(
                POSSIBLE_ENT_VALUES, 8 * len(entropy_bytes)))

    cs = len(entropy_bytes) * 8 // 32
    checksum = bytes_to_bits(bytes([sha256(entropy_bytes).digest()[0]]))[:cs]

    assert is_bit_string(checksum)
    assert len(checksum) == cs
    return checksum


def get_indices_from_entropy(entropy_bytes):
    """
    Generate indices for the given entropy.

    :param entropy_bytes: entropy; type bytes object; length must be multiple of a value in POSSIBLE_ENT_VALUES
    :return: list of indices (values 0 to 2047)
    """
    if type(entropy_bytes) is not bytes:
        raise ValueError('entropy_bytes has to be bytes object; the given type was {}'.format(type(entropy_bytes)))
    if len(entropy_bytes) * 8 not in POSSIBLE_ENT_VALUES:
        raise ValueError(
            'eight multiple of entropy_bytes length has to be in {}; '
            'the eight multiple of length of the given values was {}'.format(
                POSSIBLE_ENT_VALUES, 8 * len(entropy_bytes)))

    entropy_bits = bytes_to_bits(entropy_bytes)
    checksum_bits = get_checksum(entropy_bytes)
    bits_total = entropy_bits + checksum_bits

    assert len(bits_total) % 11 == 0
    indices_bits = [bits_total[11 * i:11 * (i + 1)] for i in range(0, len(bits_total) // 11)]
    assert ''.join(indices_bits) == bits_total
    indices = [int(x, 2) for x in indices_bits]

    ent = len(entropy_bytes) * 8
    assert len(indices) == (ent + ent // 32) // 11

    return indices


def generate_indices(ent):
    """
    Generate indices for the given entropy length.

    :param ent: entropy length; type int; possible values from POSSIBLE_ENT_VALUES
    :return: list of indices (values 0 to 2047)
    """
    if type(ent) is not int:
        raise ValueError('ent (entropy length) has to be int; the given type was {}'.format(type(ent)))
    if ent not in POSSIBLE_ENT_VALUES:
        raise ValueError(
            'ent (entropy length) has to be in {}; the given values was {}'.format(POSSIBLE_ENT_VALUES, ent))

    return get_indices_from_entropy(generate_entropy_bytes(ent))


def compose_mnemonic(indices, wordlist):
    """
    Compose the mnemonic from the given wordlist using its indices.

    :param indices: list of ints with values between 0 and 2047
    :param wordlist: list of 2048 strings
    :return: mnemonic
    """
    for i in indices:
        if type(i) is not int or not (0 <= i <= 2047):
            raise ValueError(
                'indices has to contain ints with values between 0 and 2047; the given indices were {}'.format(indices))
    for w in wordlist:
        if type(w) is not str:
            raise ValueError('wordlist has to contain only strings; the given wordlist was {}'.format(wordlist))
    if len(wordlist) != 2048:
        raise ValueError('wordlist has to have length 2048; the given wordlists had length {}'.format(len(wordlist)))

    mnemonic_list = [wordlist[i] for i in indices]
    mnemonic = ' '.join(mnemonic_list)
    return mnemonic


def get_mnemonic_from_entropy_bytes(entropy_bytes, filepath):
    """
    Get the mnemonic for the given entropy and wordlist.

    :param entropy_bytes: bytes encoding the entropy bytes
    :param filepath: filepath of the wordlist
    :return: mnemonic
    """
    if type(entropy_bytes) is not bytes:
        raise ValueError('entropy_bytes has to be bytes object; the given type was {}'.format(type(entropy_bytes)))
    if len(entropy_bytes) * 8 not in POSSIBLE_ENT_VALUES:
        raise ValueError(
            'eight multiple of entropy_bytes length has to be in {}; '
            'the eight multiple of length of the given values was {}'.format(
                POSSIBLE_ENT_VALUES, 8 * len(entropy_bytes)))

    mnemonic = compose_mnemonic(get_indices_from_entropy(entropy_bytes), get_wordlist(filepath))
    return mnemonic


def get_mnemonic_from_entropy_hex(entropy_hex, filepath):
    """
    Get the mnemonic for the given entropy and wordlist.

    :param entropy_hex: hexstring encoding the entropy bytes
    :param filepath: filepath of the wordlist
    :return: mnemonic
    """
    try:
        int(entropy_hex, 16)
    except ValueError:
        raise ValueError('the given entropy is not a hex string; the given value was {}'.format(entropy_hex))
    if len(entropy_hex) * 4 not in POSSIBLE_ENT_VALUES:
        raise ValueError(
            'four multiple of entropy hex string has to be in {}; '
            'the four multiple of the length of the given value was {}'.format(
                POSSIBLE_ENT_VALUES, 4 * len(entropy_hex)))

    mnemonic = get_mnemonic_from_entropy_bytes(bytes.fromhex(entropy_hex), filepath)
    return mnemonic


def generate_mnemonic(ent, filepath):
    """
    Generate a mnemonic from the given wordlist and for the given entropy length.

    :param ent: entropy length; type int; possible values from POSSIBLE_ENT_VALUES
    :param filepath: filepath of the wordlist
    :return: mnemonic
    """
    if type(ent) is not int:
        raise ValueError('ent (entropy length) has to be int; the given type was {}'.format(type(ent)))
    if ent not in POSSIBLE_ENT_VALUES:
        raise ValueError(
            'ent (entropy length) has to be in {}; the given values was {}'.format(POSSIBLE_ENT_VALUES, ent))

    mnemonic = compose_mnemonic(generate_indices(ent), get_wordlist(filepath))
    return mnemonic


def reverse_mnemonic(mnemonic, filepath):
    """
    Get initial entropy from mnemonic and wordlist.

    :param mnemonic: mnemonic as a string
    :param filepath: filepath of the wordlist
    :return: entropy as a hex string
    """
    if type(mnemonic) is not str:
        raise ValueError('mnemonic has to be a string; the given type was {}'.format(type(mnemonic)))

    mnemonic_list = mnemonic.split(' ')
    possible_ms_values = [x // 32 * 33 // 11 for x in POSSIBLE_ENT_VALUES]
    if len(mnemonic_list) not in possible_ms_values:
        raise ValueError('number of words in the mnemonic has to be in {}; the given number of words was {}'.format(
            possible_ms_values, len(mnemonic_list)))

    wordlist = get_wordlist(filepath)
    if len(wordlist) != 2048:
        raise ValueError('the wordlist has to have 2048 words; the given wordlist had {} words'.format(len(wordlist)))
    indices = [wordlist.index(w) for w in mnemonic_list]

    indices_bytes = [i.to_bytes(length=2, byteorder='big') for i in indices]

    indices_bits = [bytes_to_bits(b)[-11:] for b in indices_bytes]
    bit_string = ''.join(indices_bits)
    cs = len(bit_string) // 33
    bit_string = bit_string[:len(bit_string) - cs]

    return int(bit_string, 2).to_bytes(length=len(bit_string) // 8, byteorder='big').hex()


if __name__ == '__main__':
    wordlist_path = os.path.join(os.path.dirname(__file__), '../../wordlists/english.txt')
    print(generate_mnemonic(128, wordlist_path))
