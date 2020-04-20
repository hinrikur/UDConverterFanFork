
import re
import sys

from nltk.corpus.reader import CategorizedBracketParseCorpusReader
from nltk.tree import Tree


class IndexedCorpusTree(Tree):
    """
    Tree object extension with indexed constituents and corpus ID and ID number attributes
    See NLTK Tree class documentation for more: https://www.nltk.org/_modules/nltk/tree.html

    Args:
        node (tree): leaf.
        children (tree?): constituents.

    Attributes:
        _id (int): Counter for index.
        corpus_id (string): Sentence ID from original treebank, if applicable
    """

    def __init__(self, node, children=None):
        Tree.__init__(self, node, children)
        self._id = 0
        self.corpus_id = None
        self.corpus_id_num = None

    def id(self):
        """
        Returns the (leaf) index of the tree or leaf
        :return: (leaf) index of tree or leaf
        """
        return self._id

    def set_id(self, id):
        """
        Sets the (leaf) index of the tree or leaf
        """
        self._id = int(id)

    def phrases(self):
        """
        Return the "constituencies" of the tree.

        :return: a list containing this tree's "constituencies" in-order.
        :rtype: list
        """
        phrases = []
        for child in self:
            if isinstance(child, Tree):
                if len(child) > 1:
                    phrases.append(child)
                phrases.extend(child.phrases())
        return phrases

    def tags(self, filter=None):
        """18.03.20

        Returns:
            list: All PoS tags in tree.

        """

        if not filter or filter(self):
            yield self

        pos_tags = []
        for pair in self.pos():
            pos_tags.append(pair[1])
        return pos_tags

    def num_verbs(self):
        '''18.03.20

        # Based on similar method in class UniversalDependencyGraph()

        Checks by POS (IcePaHC PoS tag) how many verbs are in list of tags
        Used to estimate whether verb 'aux' UPOS is correct or wrong.
        Converter generalizes 'aux' UPOS for 'hafa' and 'vera'.

        lambda function to only check two levels of tree, not further

        Returns:
            int: Number of verb tags found in sentence.

        '''

        verb_count = 0
        for tag in self.tags(lambda t: t.height() == 2):
            # print(tag)
            if tag[0:2] in  {'VB', 'BE', 'DO', 'HV', 'MD', 'RD',}:
                verb_count += 1

        return verb_count

    def remove_nodes(self, tags=None, trace=False):
        """
        Removes all nodes from tree by specification

        # TRACE NODE REMOVAL only tested for some PP nodes

        Arguments:
            tags (list): list of node labels to remove by
            trace (boolean): true if trace nodes should be removed

        Returns: self
            type: IndexedCorpusTree

        """
        # for i in self.subtrees(filter=lambda t: t.height() == 2):
        #     if trace == True:
        #         if self[i][0][0] in {'0', '*'}:
        #             print(subtree)
        #             try:
        #                 del self[i]
        #                 # pass
        #                 # print(subtree)
        #                 # continue
        #             except ValueError:
        #                 # raise
        #                 continue
        #     if tags:
        #         for tag in tags:
        #             if subtree.label() == tag:
        #                 try:
        #                     self.remove(self[i])
        #                     # continue
        #                 except ValueError:
        #                     continue
        pairs_to_delete = []

        if tags:
            for child in self:
                if child.label() in tags:
                    self.remove(child)
            for i in reversed(self.treepositions()):
                # print(i)
                if isinstance(self[i], Tree) and self[i].height() == 2 and len(self[i]) == 1:
                    if self[i].label() in tags:
                        parent_index = i[:-1]
                        # print(self[i])
                        # print(self[parent_index])
                        pairs_to_delete.append((parent_index, i))
            for parent, child in pairs_to_delete:
                try:
                    self[parent].remove(self[child])
                except:
                    continue
            pairs_to_delete = []

        # Only set for a certain kind of PP Tree
        if trace == True:
            for i in reversed(self.treepositions()):
                if isinstance(self[i], Tree):
                    try:
                        if self[i].label() == 'PP' \
                        and len(self[i]) == 2 \
                        and self[i][1][0][0] == '*':
                            child_index = i + (1,)
                            pairs_to_delete.append((i, child_index))
                            # if len(self[i][0]) == 0:
                            #     parent_index = i[:-1]
                            #     # self[parent_index].remove(self[i])
                            #     pairs_to_delete.append((parent_index, i))
                            # elif self[i][0][0] in {'0', '*'}:
                            #     parent_index = i[:-1]
                            #     pairs_to_delete.append((parent_index, i))
                        elif self[i].label() == 'VB' \
                        and self[i].height() == 2 \
                        and self[i][0] == '*':
                            parent_index = i[:-1]
                            pairs_to_delete.append((parent_index, i))
                    except IndexError:
                        continue
            for parent, child in pairs_to_delete:

                try:
                    self[parent].remove(self[child])
                except:
                    continue
            pairs_to_delete = []

        # empty nodes removed (no args)
        for i in reversed(self.treepositions()):
            if isinstance(self[i], Tree) and len(self[i]) == 0:
                # print(self[i], len(self[i]))
                parent_index = i[:-1]
                # self[parent_index].remove(self[i])
                pairs_to_delete.append((parent_index, i))

        for parent, child in pairs_to_delete:
            try:
                # print('parent:', self[parent], len(parent))
                # print('child:',self[child], len(child))
                # child length checked, should only be 0
                if len(self[i]) == 0:
                    self[parent].remove(self[child])
                    self.remove_nodes()
                else:
                    # if designated child not empty, correct child found
                    for subtree in self[parent]:
                        if len(subtree) == 0:
                            self[parent].remove(self[child])
                            self.remove_nodes()
                    # raise(IndexedCorpusTreeError('tried to delete non-empty node'))
            except:
                continue

        # print(self)
        return self

    def remove_trace_nodes(self):
        """
        Removes trace nodes from tree

        Returns: self
            type: IndexedCorpusTree

        """
        pass
        # for subtree in self.subtrees(filter=lambda t: t.height() == 2):
        #
        #         # print(subtree)
        # return self

class IndexedCorpusTreeError(Exception):
    """docstring for ."""

    def __init__(self, *args):
        if args:
            self.message = args[0]
        else:
            self.message = None

    def __str__(self):
        print('calling str')
        if self.message:
            return 'IndexedCorpusTreeError: {0}'.format(self.message)
        else:
            return 'IndexedCorpusTreeError has been raised'



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
            tree = IndexedCorpusTree.fromstring(t, remove_empty_top_bracketing=False)
            # If there's an empty node at the top, strip it off
            if tree.label() == '' and len(tree) == 2:
                tree[0].corpus_id = str(tree[1]).strip('()ID ')
                tree[0].corpus_id_num = str(tree[1]).strip('()ID ').split(',')[1]
                return tree[0]
            else:
                return tree
            return tree

        except ValueError as e:
            sys.stderr.write("Bad tree detected; trying to recover...\n")
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
