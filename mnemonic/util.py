from .mnemonic_exceptions import (
    InvalidWordlistLength, DuplicateWords, InvalidType
)

class WordList(object):
    def __init__(self, wordlist: list):
        self.words = dict()
        self.indices = wordlist.copy()
        self.length = len(wordlist)

        wordlist.sort()
        for i in range(self.length):
            word = wordlist[i]
            if not isinstance(word, str):
                raise InvalidType(
                    'wordlist has to contain only strings; the given wordlist was {}'.format(
                        type(word)
                    )
                )
            if word in self.words:
                raise DuplicateWords(
                    "Multiple instances of word({word}) found.".format(
                        word=word
                        )
                    )
            self.words[word] = i
    
    def index_of(self, word:str) -> int:
        return self.words.get(word)
    
    def at_index(self, index:int) -> str:
        return self.indices[index]
    
    def __contains__(self, item):
        return item in self.words
    
    def __len__(self):
        return self.length

def get_wordlist(filepath):
    """
    Get list of words from the file. Each line is interpreted as a word (except the possibly empty last line).
    """
    with open(filepath, 'r') as f:
        wordlist = f.read().split('\n')
        if wordlist[-1] == '':
            wordlist.pop(-1)

        if len(wordlist) != 2048:
            raise InvalidWordlistLength('the filepath contains {} lines interpreted as words; '
                             'it should contain 2048 words'.format(len(wordlist)))

        return WordList(wordlist)
