import sys

from nltk.corpus.reader import CategorizedBracketParseCorpusReader

from ..structures.trees import IndexedCorpusTree


class IcePaHCFormatReader(CategorizedBracketParseCorpusReader):
    """24.03.20

    Extension of the NLTK CategorizedBracketParseCorpusReader class for reading mostly unedited files from the IcePaHC corpus
    See NLTK: https://www.nltk.org/_modules/nltk/corpus/reader/bracket_parse.html#CategorizedBracketParseCorpusReader
    See IcePaHC: https://linguist.is/icelandic_treebank/Icelandic_Parsed_Historical_Corpus_(IcePaHC)

    """

    def __init__(self, *args, **kwargs):
        CategorizedBracketParseCorpusReader.__init__(self, *args, **kwargs)

    def _parse(self, t):
        try:
            tree = IndexedCorpusTree.fromstring(
                t, remove_empty_top_bracketing=False, trim_id_tag=True, preprocess=True
            ).remove_nodes(tags=["CODE"], trace=True)
            # # If there's an empty node at the top, strip it off
            # if tree.label() == '' and len(tree) == 2:
            #     tree[0].corpus_id = str(tree[1]).strip('()ID ')
            #     tree[0].corpus_id_num = str(tree[1]).strip('()ID ').split(',')[1]
            #     return tree[0]
            # else:
            #     return tree
            return tree

        except ValueError as e:
            sys.stderr.write("Bad tree detected; trying to recover...\n")
            sys.stderr.write(t)
            # Try to recover, if we can:
            if e.args == ("mismatched parens",):
                for n in range(1, 5):
                    try:
                        v = IndexedCorpusTree(self._normalize(t + ")" * n))
                        sys.stderr.write(
                            "  Recovered by adding %d close " "paren(s)\n" % n
                        )
                        return v
                    except ValueError:
                        pass
            # Try something else:
            sys.stderr.write("  Recovered by returning a flat parse.\n")
            # sys.stderr.write(' '.join(t.split())+'\n')
            return IndexedCorpusTree("S", self._tag(t))
