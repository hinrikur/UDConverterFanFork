import logging

from nltk.tree import Tree
from reynir.simpletree import SimpleTree

from ..utils.joiners import NodeJoiner

logger = logging.getLogger(__name__)


class IndexedCorpusTree(Tree):
    """
    Tree object extension with indexed constituents and corpus ID and ID number attributes
    See NLTK Tree class documentation for more: https://www.nltk.org/_modules/nltk/tree.html

    2.7.20 - Added text preprocessing to fromstring method

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
        # self._trim_ID(self)

        # if self.height() == 2:
        #     if self.label() in '!"#$%&()*+, -./:;<=>?@[\]^_`{|}~' \
        #     or self.label() != 'ID' and re.match(r'\d+\.?', self[0]):
        #         self[0] = str(self[0])+'-'+(self[0])

    @classmethod
    def fromstring(
        cls, s, trim_id_tag=False, preprocess=False, remove_empty_top_bracketing=False
    ):
        """
        Extension of parent class method to check for ID tag and
        """
        j = NodeJoiner(s)
        s = "\n".join(j.lines)
        if not s == "":
            tree = super().fromstring(s)
            tree = tree[1]
            return tree

    @classmethod
    def from_simple_tree(cls, simple_tree: SimpleTree):
        """
        Class method to convert a Greynir SimpleTree instance to an IndexedCorpusTree.

        Args:
            simple_tree (SimpleTree): The SimpleTree instance to convert.

        Returns:
            IndexedCorpusTree: The converted tree as an IndexedCorpusTree instance.
        """

        tag_map = {
            "PUNCTUATION": "grm",
        }

        if simple_tree.is_terminal:
            logger.debug(f"Terminal: {simple_tree.terminal}")
            # For terminals, use the terminal string as the node label
            tag = (
                simple_tree.terminal
                if simple_tree.terminal
                else tag_map.get(simple_tree.kind, simple_tree.kind)
            )
            text = simple_tree.text
            lemma = cls("lemma", [simple_tree.lemma]) if simple_tree.lemma else None
            return cls(tag, [text, lemma])
        else:
            # For non-terminals, use the tag as the node label
            logger.debug(f"Non-terminal: {simple_tree.tag}")
            logger.debug(f"Num children: {len(list(simple_tree.children))}\n")
            # For non-terminals, recursively convert each child
            children = [cls.from_simple_tree(child) for child in simple_tree.children]
            # Use the SimpleTree's tag as the node label
            # logger.debug(f"Output tree: {cls(simple_tree.tag, children)}")
            return cls(simple_tree.tag, children)

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

    # def immmediate_tags(self):
    #     """
    #     alternate version of tags() (as filter isn't working)
    #     """
    #     pos_tags = []
    #     for child in self:
    #         pos_tags.append(child.label())
    #         for subchild in child:
    #             pos_tags.append(child.label())
    #     return pos_tags

    def num_verbs(self):
        """18.03.20

        # Based on similar method in class UniversalDependencyGraph()

        Checks by POS (IcePaHC PoS tag) how many verbs are in list of tags
        Used to estimate whether verb 'aux' UPOS is correct or wrong.
        Converter generalizes 'aux' UPOS for 'hafa' and 'vera'.

        lambda function to only check two levels of tree, not further

        Returns:
            int: Number of verb tags found in sentence.

        """

        verb_count = 0
        for tag in self.tags(lambda t: t.height() == 2):
            # for tag in self.immmediate_tags():
            # print(tag)
            if tag == "so":
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

        pairs_to_delete = []

        if tags:
            for child in self:
                if type(child) != str:
                    if child.label() in tags:
                        self.remove(child)
            for i in reversed(self.treepositions()):
                if (
                    isinstance(self[i], Tree)
                    and self[i].height() == 2
                    and len(self[i]) in {1, 2, 3, 4, 5, 6}
                ):
                    if self[i].label() in tags:
                        parent_index = i[:-1]
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
                        if (
                            self[i].label() == "PP"
                            and len(self[i]) == 2
                            and self[i][1][0][0] == "*"
                        ):
                            child_index = i + (1,)
                            pairs_to_delete.append((i, child_index))
                        elif (
                            self[i].label() == "VB"
                            and self[i].height() == 2
                            and self[i][0] == "*"
                        ):
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
                parent_index = i[:-1]
                pairs_to_delete.append((parent_index, i))

        for parent, child in pairs_to_delete:
            try:
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

        # print("clean out:\n", self)
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

    def get_lemmas(self):
        """
        Attach lemma to token
        """

        count = 0
        for i in reversed(self.treepositions()):
            if isinstance(self[i], Tree) and self[i].label() == "lemma":
                if len(self[i]) == 2 and self[i].height() == 2:
                    self[list(reversed(self.treepositions()))[count + 1]] = (
                        self[list(reversed(self.treepositions()))[count + 1]]
                        + "+lemma+"
                        + self[list(reversed(self.treepositions()))[count - 1]]
                        + "+"
                        + self[list(reversed(self.treepositions()))[count - 2]]
                    )

                elif len(self[i]) == 3 and self[i].height() == 2:
                    # The lemma is a three-word phrase
                    self[list(reversed(self.treepositions()))[count + 1]] = (
                        self[list(reversed(self.treepositions()))[count + 1]]
                        + "+lemma+"
                        + self[list(reversed(self.treepositions()))[count - 1]]
                        + "+"
                        + self[list(reversed(self.treepositions()))[count - 2]]
                        + "++"
                        + self[list(reversed(self.treepositions()))[count - 3]]
                    )

                elif len(self[i]) == 4 and self[i].height() == 2:
                    # The lemma is a four-word phrase
                    self[list(reversed(self.treepositions()))[count + 1]] = (
                        self[list(reversed(self.treepositions()))[count + 1]]
                        + "+lemma+"
                        + self[list(reversed(self.treepositions()))[count - 1]]
                        + "+"
                        + self[list(reversed(self.treepositions()))[count - 2]]
                        + "++"
                        + self[list(reversed(self.treepositions()))[count - 3]]
                        + "+++"
                        + self[list(reversed(self.treepositions()))[count - 4]]
                    )

                elif len(self[i]) == 5 and self[i].height() == 2:
                    # The lemma is a five-word phrase
                    self[list(reversed(self.treepositions()))[count + 1]] = (
                        self[list(reversed(self.treepositions()))[count + 1]]
                        + "+lemma+"
                        + self[list(reversed(self.treepositions()))[count - 1]]
                        + "+"
                        + self[list(reversed(self.treepositions()))[count - 2]]
                        + "++"
                        + self[list(reversed(self.treepositions()))[count - 3]]
                        + "+++"
                        + self[list(reversed(self.treepositions()))[count - 4]]
                        + "++++"
                        + self[list(reversed(self.treepositions()))[count - 5]]
                    )

                elif len(self[i]) == 6 and self[i].height() == 2:
                    # The lemma is a six-word phrase
                    self[list(reversed(self.treepositions()))[count + 1]] = (
                        self[list(reversed(self.treepositions()))[count + 1]]
                        + "+lemma+"
                        + self[list(reversed(self.treepositions()))[count - 1]]
                        + "+"
                        + self[list(reversed(self.treepositions()))[count - 2]]
                        + "++"
                        + self[list(reversed(self.treepositions()))[count - 3]]
                        + "+++"
                        + self[list(reversed(self.treepositions()))[count - 4]]
                        + "++++"
                        + self[list(reversed(self.treepositions()))[count - 5]]
                        + "+++++"
                        + self[list(reversed(self.treepositions()))[count - 6]]
                    )

                else:
                    # The lemma is attached to the phrase above
                    self[list(reversed(self.treepositions()))[count + 1]] = (
                        self[list(reversed(self.treepositions()))[count + 1]]
                        + "+lemma+"
                        + self[list(reversed(self.treepositions()))[count - 1]]
                    )

            count += 1
        return self

    def multiword_expression(self):
        """
        Define single-phrase MWEs as one token
        """

        count = 0
        for i in reversed(self.treepositions()):
            if (
                isinstance(self[i], Tree)
                and len(self[i]) == 2
                and self[i].height() == 2
                and "+"
                not in self[
                    list(reversed(self.treepositions()))[count - 1]
                ]  # The phrase hasn't gone through if loop before      # TODO: doesn't have an impact, all tokens have +lemma+
            ):
                self[list(reversed(self.treepositions()))[count - 1]] = (
                    self[list(reversed(self.treepositions()))[count - 1]]
                    + "+"
                    + self[list(reversed(self.treepositions()))[count - 2]]
                )

            elif (
                isinstance(self[i], Tree)
                and len(self[i]) == 3
                and self[i].height() == 2
                and "+"
                not in self[
                    list(reversed(self.treepositions()))[count - 1]
                ]  # The phrase hasn't gone through if loop before
            ):
                self[list(reversed(self.treepositions()))[count - 1]] = (
                    self[list(reversed(self.treepositions()))[count - 1]]
                    + "+"
                    + self[list(reversed(self.treepositions()))[count - 2]]
                    + "++"
                    + self[list(reversed(self.treepositions()))[count - 3]]
                )

            elif (
                isinstance(self[i], Tree)
                and len(self[i]) == 4
                and self[i].height() == 2
                and "+"
                not in self[
                    list(reversed(self.treepositions()))[count - 1]
                ]  # The phrase hasn't gone through if loop before
            ):
                # Four-word phrase
                self[list(reversed(self.treepositions()))[count - 1]] = (
                    self[list(reversed(self.treepositions()))[count - 1]]
                    + "+"
                    + self[list(reversed(self.treepositions()))[count - 2]]
                    + "++"
                    + self[list(reversed(self.treepositions()))[count - 3]]
                    + "+++"
                    + self[list(reversed(self.treepositions()))[count - 4]]
                )

            elif (
                isinstance(self[i], Tree)
                and len(self[i]) == 5
                and self[i].height() == 2
                and "+"
                not in self[
                    list(reversed(self.treepositions()))[count - 1]
                ]  # The phrase hasn't gone through if loop before
            ):
                # Five-word phrase
                self[list(reversed(self.treepositions()))[count - 1]] = (
                    self[list(reversed(self.treepositions()))[count - 1]]
                    + "+"
                    + self[list(reversed(self.treepositions()))[count - 2]]
                    + "++"
                    + self[list(reversed(self.treepositions()))[count - 3]]
                    + "+++"
                    + self[list(reversed(self.treepositions()))[count - 4]]
                    + "++++"
                    + self[list(reversed(self.treepositions()))[count - 5]]
                )

            elif (
                isinstance(self[i], Tree)
                and len(self[i]) == 6
                and self[i].height() == 2
                and "+"
                not in self[
                    list(reversed(self.treepositions()))[count - 1]
                ]  # The phrase hasn't gone through if loop before
            ):
                # Six-word phrase
                self[list(reversed(self.treepositions()))[count - 1]] = (
                    self[list(reversed(self.treepositions()))[count - 1]]
                    + "+"
                    + self[list(reversed(self.treepositions()))[count - 2]]
                    + "++"
                    + self[list(reversed(self.treepositions()))[count - 3]]
                    + "+++"
                    + self[list(reversed(self.treepositions()))[count - 4]]
                    + "++++"
                    + self[list(reversed(self.treepositions()))[count - 5]]
                    + "+++++"
                    + self[list(reversed(self.treepositions()))[count - 6]]
                )

            count += 1

        return self


class IndexedCorpusTreeError(Exception):
    """docstring for ."""

    def __init__(self, *args):
        if args:
            self.message = args[0]
        else:
            self.message = None

    def __str__(self):
        print("calling str")
        if self.message:
            return "IndexedCorpusTreeError: {0}".format(self.message)
        else:
            return "IndexedCorpusTreeError has been raised"
