import unittest
import json
import os
from mnemonic.mnemonic import get_mnemonic_from_entropy_hex, get_mnemonic_from_entropy_bytes, reverse_mnemonic, \
    generate_entropy_bytes, POSSIBLE_ENT_VALUES


class MnemonicTest(unittest.TestCase):

    def test_english_vectors(self):
        vectors_path = os.path.join(os.path.dirname(__file__), 'vectors/english.json')
        wordlist_path = os.path.join(os.path.dirname(__file__), '../wordlists/english.txt')

        with open(vectors_path, 'r') as f:
            for v in json.loads(f.read())['english']:
                # test get_mnemonic_from_entropy_hex
                expected = v[1]
                actual = get_mnemonic_from_entropy_hex(v[0], wordlist_path)
                self.assertEqual(expected, actual)

                # test get_mnemonic_from_entropy_bytes
                expected = v[1]
                actual = get_mnemonic_from_entropy_bytes(bytes.fromhex(v[0]), wordlist_path)
                self.assertEqual(expected, actual)

                # test reverse_mnemonic
                expected = v[0]
                actual = reverse_mnemonic(v[1], wordlist_path)
                self.assertEqual(expected, actual)

    # not strictly unit test (uses randomness from the system)
    def test_random_entropy(self):
        wordlist_path = os.path.join(os.path.dirname(__file__), '../wordlists/english.txt')

        for ent in POSSIBLE_ENT_VALUES:
            entropy_bytes_prev = generate_entropy_bytes(ent)
            for _ in range(0, 1000):
                entropy_bytes = generate_entropy_bytes(ent)

                # doesn't strictly have to hold (so sometimes will fail), but may detect very bad random generators
                assert entropy_bytes_prev != entropy_bytes

                mnemonic = get_mnemonic_from_entropy_bytes(entropy_bytes, wordlist_path)
                entropy2_hex = reverse_mnemonic(mnemonic, wordlist_path)
                self.assertEqual(entropy_bytes.hex(), entropy2_hex)

                entropy_bytes_prev = entropy_bytes


if __name__ == '__main__':
    unittest.main()
