import re


from collections import defaultdict
from nltk.parse import DependencyGraph

from ..utils.joiners import NodeJoiner
from ..utils.tools import decode_escaped
from ..utils.conversion import create_dependency_graph


class UniversalDependencyGraph(DependencyGraph):
    """
    Takes in a nltk Tree object and returns an approximation of the tree
    sentence in the CONLLU format for UD:
        ID: Word index, integer starting at 1 for each new sentence.
        FORM: Word form or punctuation symbol.
        LEMMA: Lemma or stem of word form.
        UPOS: Universal part-of-speech tag.
        XPOS: Language-specific part-of-speech tag; underscore if not available.
        FEATS: List of morphological features from the universal feature
            inventory or from a defined language-specific extension; underscore
            if not available.
        HEAD: Head of the current word, which is either a value of ID or
            zero (0).
        DEPREL: Universal dependency relation to the HEAD (root iff HEAD = 0)
            or a defined language-specific subtype of one.
        DEPS: Enhanced dependency graph in the form of a list of head-deprel
            pairs.
        MISC: Any other annotation.
    """

    def __init__(self, tree=None, **kwargs):
        super().__init__(**kwargs)
        self.tree = tree

        self.nodes = defaultdict(
            lambda: {
                "address": None,
                "word": None,
                "lemma": None,
                "ctag": None,  # upostag
                "tag": None,  # xpostag
                "feats": defaultdict(lambda: None),
                "head": "_",  # None, # TODO: find permanent fix!
                "deps": defaultdict(list),
                "rel": None,
                "misc": defaultdict(lambda: None),  # testing adding Misc column
            }
        )
        self.nodes[0].update(
            {
                "ctag": "TOP",
                "tag": "TOP",
                "ID": 0,
            }
        )
        self.original_ID = None

        if tree is not None:
            create_dependency_graph(self, tree)

    def _deps_str(self, deps_dict):
        # todo, format should be "4:nsubj|11:nsubj", see http://universaldependencies.github.io/docs/format.html
        return "_"  # return ''.join('%s:%s,' % (dep, '+'.join(str(rel))) for (dep, rel) in deps_dict.items())[0:-1]

    def _dict_to_string(self, dict):
        """17.03.20

        Returns:
                string: contents of column column for word from defaultdict.
                        ex. {'SpaceAfter' : 'No'} -> 'SpaceAfter=No'
                        If dict is None returns '_'

        """

        return (
            "|".join(
                f"{pair[0]}={pair[1]}"
                for pair in sorted(dict.items(), key=lambda s: s[0].lower())
                if pair[1] is not None
            )
            if dict and len(dict) != 0 and dict != "_"
            else "_"
        )

    def addresses(self):
        """10.03.20
        Gets addresses of the dependency graph.

        Returns:
            tuple: all addresses in dependency graph of sentence.

        """

        return tuple(
            address
            for address in [node["address"] for node in self.nodes.values()]
            if address != None
        )

    def rels(self):
        """
        Checks and counts the relations in the sentence

        Returns:
            defaultdict: Relations found in the sentence graph, counted.
        """
        rels = defaultdict(int)
        rels["root"] = 0
        rels["ccomp/xcomp"] = 0
        for node in self.nodes.values():
            rels[node["rel"]] += 1
        return rels

    def ctags(self):
        """
        Checks and counts the IcePaHC tags in the sentence

        Returns:
            defaultdict: IcePaHC tags found in the sentence graph, counted.
        """
        ctags = defaultdict(int)
        for node in self.nodes.values():
            ctags[node["ctag"]] += 1
        return ctags

    def num_roots(self):
        """
        Method for checking the root relation in the graph.
        There must be one relation to the root node in each sentence, no more
        no less. This should return 1 if sentence is correctly parsed.

        Returns:
            int: Number of root relations found in sentence.
        """
        return self.rels()["root"]

    def root_address(self):
        """
        Method for finding the sentence root's address.

        Returns:
            int: Address of the sentence root.
        """
        for address, node in self.nodes.items():
            if node["rel"] == "root":
                return address

    def num_verbs(self):
        """09.03.20
        Checks by GC POS (GreynirCorpus PoS tag) how many verbs are in sent. graph.
        Used to estimate whether verb 'aux' UPOS is correct or wrong.
        Converter generalizes 'aux' UPOS for 'hafa' and 'vera'.

        Returns:
            int: Number of verb tags found in sentence.

        # TODO: Finish implementation
        """

        verb_count = 0
        for node in self.nodes.values():
            if node["tag"] == None:
                continue
            elif node["tag"][0:2] == "so":
                verb_count += 1

        return verb_count

    def num_subj(self):
        """
        Returns a set of the words whose deprel is 'nsubj' or 'csubj' and whose head is the same.
        """
        from itertools import chain

        if (
            self.rels()["nsubj"] > 1
            or (self.rels()["nsubj"] == 1 and self.rels()["csubj"] == 1)
            or self.rels()["csubj"] > 1
        ):
            subjs = {}
            for node in self.nodes.items():
                if node[1]["rel"] == "nsubj" or node[1]["rel"] == "csubj":
                    subjs[node[1]["word"]] = node[1]["head"]

        rev_dict = {}
        for key, value in subjs.items():
            rev_dict.setdefault(value, set()).add(key)

        result = set(
            chain.from_iterable(
                values for key, values in rev_dict.items() if len(values) > 1
            )
        )

        return result

    def join_output_nodes(self, conllU):
        """
        Joins clitics in CoNLLU string output with NodeJoiner class
        """
        nj = NodeJoiner(conllU.split("\n"))
        for n in reversed(nj.indexes):
            # Various clitics processed
            nj.join_clitics(n)
            nj.join_other_nodes(n)
        conllU = "\n".join(nj.lines)
        return conllU

    def to_conllU(self):
        """
        The dependency graph in CoNLL-U (Universal) format.

        Consists of one or more word lines, and word lines contain the following fields:

        ID: Word index, integer starting at 1 for each new sentence; may be a range for tokens with multiple words.
        FORM: Word form or punctuation symbol.
        LEMMA: Lemma or stem of word form.
        UPOSTAG: Universal part-of-speech tag drawn from our revised version of the Google universal POS tags.
        XPOSTAG: Language-specific part-of-speech tag; underscore if not available.
        FEATS: List of morphological features from the universal feature inventory or from a defined language-specific extension; underscore if not available.
        HEAD: Head of the current token, which is either a value of ID or zero (0).
        DEPREL: Universal Stanford dependency relation to the HEAD (root iff HEAD = 0) or a defined language-specific subtype of one.
        DEPS: List of secondary dependencies (head-deprel pairs).
        MISC: Any other annotation.

        :rtype: str

        # TODO: _misc_string
        """

        template = "{i}\t{word}\t{lemma_str}\t{ctag}\t{tag}\t{feats_str}\t{head}\t{rel}\t{deps_str}\t{misc_str}\n"

        try:
            return self.join_output_nodes(
                "".join(
                    template.format(
                        i=i,
                        **node,
                        lemma_str=node["lemma"] if node["lemma"] else "_",
                        deps_str=self._deps_str(node["deps"]),
                        feats_str=self._dict_to_string(node["feats"]),
                        misc_str=self._dict_to_string(node["misc"]),
                    )
                    for i, node in self.nodes.items()  # sorted(self.nodes.items())
                    if node["tag"] != "TOP" and node["word"] is not None
                )
                + "\n"
            )
        except TypeError:
            print(self.nodes.keys())
            print(self.nodes.items())
            raise

    def plain_text(self):
        """09.03.20
        Extracts text from dependency graph.
        - Removes '$' from conjoined words and joins word-parts using regex

        # TODO: Fix spacing ambiguous quotation marks: ",\'

        Returns:
            string: String representation of sentence text

        """

        text = []
        for address, node in self.nodes.items():
            if type(address) != str:
                # print(address, node)
                if node["word"] == None:
                    continue
                elif "SpaceAfter" in node["misc"] or address == len(self.nodes):
                    text.append(decode_escaped(node["word"]))
                else:
                    text.append(decode_escaped(node["word"] + " "))
        text = "".join(text)
        text = re.sub(r"(?<=\S)\$(?=\S)", "", text)
        text = re.sub(r"\$ \$", "", text)
        text = re.sub(r"\$\$", "", text)
        text = re.sub(r" \$", " ", text)
        text = re.sub(r"\$ ", " ", text)
        text = re.sub(r" $", "", text)
        text = re.sub(r"(?<!:) ,", ",", text)
        text = re.sub(r" \.", ".", text)
        text = re.sub(r"\( ", "(", text)
        text = re.sub(r" \)", ")", text)
        text = re.sub(r" \?", "?", text)
        text = re.sub(r" ;", ";", text)
        text = re.sub(r" :", ":", text)
        text = re.sub(r"„ ", "„", text)
        text = re.sub(r" “", "“", text)
        text = re.sub(r" – ", "–", text)

        return "# text = " + text

    def original_ID_plain_text(self, **kwargs):
        """Short summary.

        Returns:
            type: .

        """

        if isinstance(self.original_ID, list):
            return (
                "# "
                + kwargs.get("corpus_name", "X")
                + "_IDs = "
                + " ; ".join(self.original_ID)
            )
        else:
            return (
                "# " + kwargs.get("corpus_name", "X") + "_ID = " + str(self.original_ID)
            )
