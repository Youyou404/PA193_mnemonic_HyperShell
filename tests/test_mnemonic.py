import unittest
import json
import os
from mnemonic.mnemonic import get_mnemonic_from_entropy_hex, get_mnemonic_from_entropy_bytes, reverse_mnemonic, \
    generate_seed


class MnemonicTest(unittest.TestCase):

    def test_english_vectors(self):
        vectors_path = os.path.join(os.path.dirname(__file__), "vectors/english.json")
        wordlist_path = os.path.join(os.path.dirname(__file__), "../wordlists/english.txt")

        with open(vectors_path, "r") as f:
            for v in json.loads(f.read())["english"]:
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

                # test generate_seed
                expected = v[2]
                actual = generate_seed(v[1])
                self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
