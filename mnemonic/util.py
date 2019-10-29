def get_wordlist(filepath):
    """
    Get list of words from the file. Each line is interpreted as a word (except the possibly empty last line).
    """
    with open(filepath, 'r') as f:
        wordlist = f.read().split('\n')
        if wordlist[-1] == '':
            wordlist.pop(-1)

        if len(wordlist) != 2048:
            raise ValueError('the filepath contains {} lines interpreted as words; '
                             'it should contain 2048 words'.format(len(wordlist)))

        return wordlist
