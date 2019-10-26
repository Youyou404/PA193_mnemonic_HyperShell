import unittest
from src.libs.mnemonic import get_mnemonic
import json


class MnemonicTest(unittest.TestCase):

    def test_english_vectors(self):
        with open("vectors/english.json", "r") as f:
            for v in json.loads(f.read())["english"]:
                expected = v[1]
                actual = " ".join(get_mnemonic(v[0], "../../wordlists/english.txt"))
                self.assertEqual(expected, actual)
