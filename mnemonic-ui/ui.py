import argparse
from mnemonic.mnemonic import POSSIBLE_ENT_VALUES, generate_entropy_bytes, get_mnemonic_from_entropy_bytes, \
    reverse_mnemonic
from mnemonic.seed import generate_seed

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='User interface showcasing the mnemonics library.')

    # entropy sub parser
    subparsers = parser.add_subparsers(title='commands', dest='command')
    parser_entropy = subparsers.add_parser('entropy', help='generate random entropy, get entropy from mnemonic')
    parser_entropy.add_argument('-mn', dest='entropy_mnemonic', help='mnemonic to reverse', metavar='mnemonic')
    parser_entropy.add_argument('-wl', dest='entropy_wordlist_path', help='wordlist for reversing mnemonic',
                                metavar='path')
    parser_entropy.add_argument('-l', type=int, default=POSSIBLE_ENT_VALUES[0], dest='entropy_ent',
                                help='bit length of generated entropy', metavar='length')

    # mnemonic sub parser
    parser_mnemonic = subparsers.add_parser('mnemonic', help='generate mnemonic')
    parser_mnemonic.add_argument('-e', dest='mnemonic_entropy', help='entropy', metavar='entropy')
    parser_mnemonic.add_argument('-wl', dest='mnemonic_wordlist_path', help='wordlist file path', metavar='path')

    # seed sub parser
    parser_seed = subparsers.add_parser('seed', help='seed functionality')
    parser_seed.add_argument('-e', dest='seed_entropy', help='entropy', metavar='entropy')
    parser_seed.add_argument('-mn', dest='seed_mnemonic', help='mnemonic', metavar='mnemonic')
    parser_seed.add_argument('-s', dest='seed_seed', help='seed', metavar='seed')
    parser_seed.add_argument('-wl', dest='seed_wordlist', help='wordlist file path', metavar='path')
    parser_seed.add_argument('-p', dest='seed_passphrase', help='passphrase', metavar='passphrase')

    args = parser.parse_args()
    # entropy functionality
    if args.command == 'entropy':
        # reverse mnemonic
        if args.entropy_mnemonic is not None:
            if args.entropy_wordlist_path is None:
                wordlist_path = '../wordlists/english.txt'
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
    elif args.command == 'mnemonic':
        # generate mnemonic
        if args.mnemonic_entropy is None:
            entropy_bytes = generate_entropy_bytes(POSSIBLE_ENT_VALUES[0])
        else:
            entropy_bytes = bytes.fromhex(args.mnemonic_entropy)

        if args.mnemonic_wordlist_path is None:
            wordlist_path = '../wordlists/english.txt'
        else:
            wordlist_path = args.mnemonic_wordlist_path

        mnemonic = get_mnemonic_from_entropy_bytes(entropy_bytes, wordlist_path)
        print(mnemonic)
    # seed functionality
    elif args.command == 'seed':
        # process the wordlist
        if args.seed_wordlist is None:
            wordlist_path = '../wordlists/english.txt'
        else:
            wordlist_path = args.seed_wordlist

        # verify a given seed against a given entropy
        if args.seed_seed is not None and args.seed_entropy is not None and args.seed_mnemonic is None:
            mnemonic = get_mnemonic_from_entropy_bytes(args.seed_entropy, wordlist_path)
            seed = generate_seed(mnemonic, args.seed_passphrase, wordlist_path)
            if seed == args.seed_seed:
                print("The given entropy match the given seed")
            else:
                print("The given entropy does not match the given seed")
        # verify a given seed seed against a given mnemonic
        elif args.seed_seed is not None and args.seed_mnemonic is not None and args.seed_entropy is None:
            seed = generate_seed(args.seed_mnemonic, args.seed_passphrase, wordlist_path)
            if seed == args.seed_seed:
                print("The given mnemonic match the given seed")
            else:
                print("The given mnemonic does not match the given seed")
        # generate a seed from a given entropy
        elif args.seed_entropy is not None and args.seed_mnemonic is None and args.seed_seed is None:
            mnemonic = get_mnemonic_from_entropy_bytes(args.seed_entropy, wordlist_path)
            seed = generate_seed(mnemonic, args.seed_passphrase, wordlist_path)
            print(seed)
        # generate seed from a given mnemonic
        elif args.seed_mnemonic is not None and args.seed_entropy is None and args.seed_seed is None:
            seed = generate_seed(args.seed_mnemonic, args.seed_passphrase, wordlist_path)
            print(seed)

    # print help
    else:
        parser.parse_args(['--help'])
