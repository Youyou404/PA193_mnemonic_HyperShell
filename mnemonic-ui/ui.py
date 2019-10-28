import argparse
from mnemonic.mnemonic import POSSIBLE_ENT_VALUES, generate_entropy_bytes, get_mnemonic_from_entropy_bytes, \
    reverse_mnemonic

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="User interface showcasing the mnemonics library.")

    # entropy sub parser
    subparsers = parser.add_subparsers(title="commands", dest="command")
    parser_entropy = subparsers.add_parser("entropy", help="generate random entropy, get entropy from mnemonic")
    parser_entropy.add_argument("-mn", dest="entropy_mnemonic", help="mnemonic to reverse", metavar="mnemonic")
    parser_entropy.add_argument("-wl", dest="entropy_wordlist_path", help="wordlist for reversing mnemonic",
                                metavar="path")
    parser_entropy.add_argument("-l", type=int, default=POSSIBLE_ENT_VALUES[0], dest="entropy_ent",
                                help="bit length of generated entropy", metavar="length")

    # mnemonic sub parser
    parser_mnemonic = subparsers.add_parser("mnemonic", help="generate mnemonic")
    parser_mnemonic.add_argument("-e", dest="mnemonic_entropy", help="entropy", metavar="entropy")
    parser_mnemonic.add_argument("-wl", dest="mnemonic_wordlist_path", help="wordlist file path", metavar="path")

    # seed sub parser
    # TODO
    parser_seed = subparsers.add_parser("seed", help="seed functionality")

    args = parser.parse_args()
    # entropy functionality
    if args.command == "entropy":
        # reverse mnemonic
        if args.entropy_mnemonic is not None:
            if args.entropy_wordlist_path is None:
                wordlist_path = "../wordlists/english.txt"
            else:
                wordlist_path = args.entropy_wordlist_path
            entropy = reverse_mnemonic(args.entropy_mnemonic, wordlist_path)
            print(entropy)
        # generate random seed
        else:
            ent = args.entropy_ent
            entropy = generate_entropy_bytes(ent).hex()
            print(entropy)
    # mnemonic functionality
    elif args.command == "mnemonic":
        # generate mnemonic
        if args.mnemonic_entropy is None:
            entropy_bytes = generate_entropy_bytes(POSSIBLE_ENT_VALUES[0])
        else:
            entropy_bytes = bytes.fromhex(args.mnemonic_entropy)

        if args.mnemonic_wordlist_path is None:
            wordlist_path = "../wordlists/english.txt"
        else:
            wordlist_path = args.mnemonic_wordlist_path

        mnemonic = get_mnemonic_from_entropy_bytes(entropy_bytes, wordlist_path)
        print(mnemonic)
    # seed functionality
    elif args.command == "seed":
        # TODO generate seed from entropy
        # TODO generate seed from mnemonic
        # TODO check given mnemonic generates given seed
        pass
    # print help
    else:
        parser.parse_args(["--help"])
