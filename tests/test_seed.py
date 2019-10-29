import unittest
import json
import os
from seed.seed import generate_seed


class SeedTest(unittest.TestCase):

    def test_english_vectors(self):
        vectors_path = os.path.join(os.path.dirname(__file__), "vectors/english.json")
        wordlist_path = os.path.join(os.path.dirname(__file__), "../wordlists/english.txt")

        with open(vectors_path, "r") as f:
            for v in json.loads(f.read())["english"]:
                # test generate_seed
                expected = v[2]
                actual = generate_seed(v[1])
                self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
