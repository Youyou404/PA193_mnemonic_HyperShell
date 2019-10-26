import unittest
from mnemonic.libs.mnemonic import get_mnemonic_from_entropy_hex, get_mnemonic_from_entropy_bytes, reverse_mnemonic
import json


class MnemonicTest(unittest.TestCase):

    def test_english_vectors(self):
        with open("vectors/english.json", "r") as f:
            for v in json.loads(f.read())["english"]:
                # test get_mnemonic_from_entropy_hex
                expected = v[1]
                actual = get_mnemonic_from_entropy_hex(v[0], "../wordlists/english.txt")
                self.assertEqual(expected, actual)

                # test get_mnemonic_from_entropy_bytes
                expected = v[1]
                actual = get_mnemonic_from_entropy_bytes(bytes.fromhex(v[0]), "../wordlists/english.txt")
                self.assertEqual(expected, actual)

                # test reverse_mnemonic
                expected = v[0]
                actual = reverse_mnemonic(v[1], "../wordlists/english.txt")
                self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
