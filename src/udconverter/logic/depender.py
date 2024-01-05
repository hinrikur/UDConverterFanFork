"""
depender.py
Hinrik Hafsteinsson (hinhaf@hi.is)
Þórunn Arnardóttir (thar@hi.is)
2019
Based on earlier work by
Örvar Kárason (ohk2@hi.is)
Part of UniTree project for IcePaHC
"""

import re
import logging

from collections import defaultdict
from nltk.tree import Tree


from .features import G_Features
from ..structures.graphs import IndexedCorpusTree, UniversalDependencyGraph
from ..static.rules import head_rules
from ..utils.tools import determine_relations
from ..utils import dg_utils

logger = logging.getLogger(__name__)


class Converter:
    """
    Converts constituency tree to dependency tree

    Attributes:
        t (type): IndexedCorpusTree object being converted.
        dg (type): UnviersalDependencyGraph object.

    """

    def __init__(self, auto_tags=False):
        # todo read rules from config file
        self.t = None
        self.dg = None
        self.const = []
        self.singles = []
        self.tag_list = {}
        self.auto_tags = auto_tags
        self.tagged_sentences = None

    def set_tag_dict(self, tag_dict):
        self.tagged_sentences = tag_dict

    def _select_head(self, tree, main_clause=None):
        """
        Selects dependency head of a tree object, specifically a constituency
        tree (i.e. small part) of a bigger sentence

        Args:
            tree (IndexedCorpusTree): IndexedCorpusTree object to have head selected
        """

        tag = str(tree.label())

        # print(tag)

        # apparently it's better to generalize this over all tags
        tag = re.sub(r"[=-]\d+", "", tag)

        # # DEBUG:
        # print(f'Tree: ({tree.label()}), length: {len(tree)}, height: {tree.height()}\n', tree, tag)
        # input()

        new_rules = []
        head_rule = head_rules.get(
            tag, {"dir": "r", "rules": [".*"]}
        )  # default rule, first from left
        rules = head_rule["rules"]
        dir = head_rule["dir"]
        head = None  # NOTE: er þetta eitthvað?

        if not main_clause:
            main_clause = tree

        # Somewhat efficient fix for aux verbs
        if tree.num_verbs() == 1 or main_clause.num_verbs() == 1:
            new_rules[0:0] = rules
            # new_rules[4:4] = ['BE.*', 'HV.*', 'MD.*', 'RD.*']
            # new_rules[4:4] = ["HV.*", "MD.*", "RD.*"]
            rules = new_rules

        # TEMP: testing for 3 verb sentences where the 'first' verb is 'vera', e.g. 'En það var eftir að hann var farinn sem mér varð ljóst að ég yrði'
        elif tree.num_verbs() > 2 or main_clause.num_verbs() > 2:
            # print('\n3 verb sentence\n')
            new_rules[0:0] = rules
            # new_rules[4:4] = ["IP-INF", "HV.*", "MD.*", "RD.*"]
            # new_rules.append("BE.*")
            rules = new_rules

        # # DEBUG:
        # print(len(new_rules))
        # input()

        if dir == "l":
            rules = reversed(rules)

        # For catching relation to main clause verb

        # # DEBUG
        # print('MC:\n',main_clause)
        # print('Verb num:\n',tree.num_verbs())

        for rule in rules:
            if not str(main_clause).startswith("(lemma"):
                for child in main_clause:
                    # print("Main clause: ", main_clause)
                    if not isinstance(child, Tree):
                        # print("Main clause: ", main_clause)
                        id = "_"
                        label = "_"
                    else:
                        id = child.id()
                        label = child.label()
                    try:
                        # if child.height() == 2 and child[0][0] == "*":
                        #    continue

                        # # DEBUG:
                        # print(rule, child.label())
                        # print(child,'\n')

                        if re.fullmatch(rule, label):
                            # # DEBUG:
                            # print('Head rules:', rules)
                            # input()

                            if type(id) == int:
                                tree.set_id(id)

                            # # DEBUG
                            # print('Head:\n',child)
                            # input()

                            return
                    except AttributeError:
                        # print("child:", child)
                        # print(type(child))
                        raise

        # no head-rules applicable: select either the first or last child as head
        if len(tree) == 0:
            # print('==no_head==')
            tree.set_id(
                999
            )  # For when there is no terminal node in head (text edit artifact)
        elif dir == "l":
            tree.set_id(tree[-1].id())

        elif not str(tree).startswith("(lemma"):
            # print('\tNo head rule found\n')
            tree.set_id(
                # tree[0].id()
                tree[0].id()
            )  # first from left indicated or no head rule index found

            # # DEBUG:
            # print('Head rules:', rules)
            # input()
            # # DEBUG:
            # print('Head:\n',child)
            # input()

    def _relation(self, mod_tag, head_tag, node):
        """
            Return a Universal Relation name given an IcePaHC/Penn phrase-type tag

            http://www.linguist.is/icelandic_treebank/Phrase_Types
            to
            http://universaldependencies.github.io/docs/u/dep/index.html

        :param mod_tag: str
        :param head_tag: str
        :return: str
        """

        # return mod_tag, head_tag

        if "-" in mod_tag:
            mod_tag, mod_func = mod_tag.split("-", 1)
        elif "_" in mod_tag:
            mod_tag, mod_func = mod_tag.split("_", 1)
        else:
            mod_func = None

        if "-" in head_tag:
            head_tag, head_func = head_tag.split("-", 1)
        elif "_" in head_tag:
            head_tag, head_func = head_tag.split("_", 1)
        else:
            head_func = None

        return determine_relations(mod_tag, mod_func, head_tag, head_func, node)

    def from_string(self, tree_string):
        """Process tree from string."""
        tree = IndexedCorpusTree.fromstring(tree_string)
        return self.process_tree(tree)

    def from_corpus_tree(self, tree):
        """Process tree from IndexedCorpusTree."""
        return self.process_tree(tree)

    def process_tree(self, tree):
        """Common processing for all tree types."""
        tree = tree.get_lemmas()
        # Check if tree is still an instance of IndexedCorpusTree, process accordingly
        if isinstance(tree, IndexedCorpusTree):
            tree = tree.remove_nodes(
                tags=[
                    "META",
                    "IP-CORPUS",
                    "ID-LOCAL",
                    "URL",
                    "COMMENT",
                    "lemma",
                    "exp_seg",
                    "exp_abbrev",
                ],
                trace=True,
            )
        else:
            tree = IndexedCorpusTree.fromstring(tree).remove_nodes(
                tags=[
                    "META",
                    "IP-CORPUS",
                    "ID-LOCAL",
                    "URL",
                    "COMMENT",
                    "lemma",
                    "exp_seg",
                    "exp_abbrev",
                ],
                trace=True,
            )
        return tree

    def create_dependency_graph(self, tree):
        """Create a dependency graph from a phrase structure tree.

        Returns:
            type: .

        """
        # const = []
        # tag_list = {}
        # nr = 1

        t = (
            self.from_corpus_tree(tree)
            if isinstance(tree, IndexedCorpusTree)
            else self.from_string(tree)
        )

        self.dg = UniversalDependencyGraph()

        for i in t.treepositions():
            self.process_tree_node(t, i)

        # trees with single child
        singles = self.identify_singles(t)

        # go through the constituencies (bottom up) and find their heads
        self.const.sort(key=lambda x: len(x), reverse=True)

        self.finalize_dependency_graph(singles, t)

        return self.dg

    def finalize_dependency_graph(self, singles, t):
        """Finalize the dependency graph after processing all nodes."""
        # head selection
        self.select_graph_heads(self.const, singles, t)

        # relations set
        self.set_graph_relations(self.const, t)

        # NOTE: Here call method to fix dependency graph if needed?
        self.fix_graph()

    def identify_singles(self, t):
        """Identify single children and constituency structures in the tree."""
        singles = [
            i
            for i in set(t.treepositions()).difference(self.cont)
            if isinstance(t[i], Tree)
        ]
        return singles

    def process_tree_node(self, t, i):
        if isinstance(t[i], Tree):
            if len(t[i]) == 1:
                # If terminal node with label or tree with single child
                # e.g. (VBDI tók-taka) or (NP-SBJ (PRO-N hann-hann))
                self.tag_list[nr] = t[i].label()
                t[i].set_id(nr)
            elif len(t[i]) in {2, 3, 4, 5, 6} and t[i].height() == 2:
                # If terminal node with multiword expression/phrase with up to 6 tokens
                self.tag_list[nr] = t[i].label()
                t[i].set_id(nr)
                t[i].multiword_expression()

            else:
                # If constituent / complex phrase
                # e.g. (ADVP (ADV smám-smám) (ADV saman-saman))
                t[i].set_id(0)
                self.const.append(i)

        else:
            # temp_form = t[i]
            # temp_lemma = None
            # if "+lemma+" in t[i]:
            #    temp_form, temp_lemma = t[i].split("+lemma+")
            # if (
            #    (
            #        (temp_form in string.punctuation or temp_form in "„“")
            #        and temp_lemma is None
            #    )
            #    or ("+" in temp_form and "+" in temp_lemma)
            #    or (
            #        "+" not in temp_form
            #        and temp_lemma is not None
            #        and "+" not in temp_lemma
            #    )
            #    or ("+" in temp_form and "+" not in temp_lemma)
            # ):
            if t[i] == "\\":
                print(
                    "The token is a backslash, which most likely precedes a bracket. Please exchange the '\(' for *opening_bracket* and the '\)' for *closing_bracket*"
                )
            if len(self.tag_list) > 0:
                try:
                    tag = self.tag_list[nr]
                except KeyError:
                    form = t[i].split("+lemma+")[0]
                    nr -= len(FORM.split(" "))
                    tag = self.tag_list[nr]
            else:
                tag = None

            if "+lemma+" in t[i]:
                FORM = t[i].split("+lemma+")[0]
                LEMMA = t[i].split("+lemma+")[1]
            else:
                FORM = t[i]
                LEMMA = None

            if "+" in FORM:
                # The token is a multiword expression/phrase
                FORM = FORM.replace("+++++", " ")
                FORM = FORM.replace("++++", " ")
                FORM = FORM.replace("+++", " ")
                FORM = FORM.replace("++", " ")
                FORM = FORM.replace("+", " ")

            if LEMMA is not None and "+" in LEMMA:
                # The lemma is a multiword expression
                LEMMA = LEMMA.replace("+++++", " ")
                LEMMA = LEMMA.replace("++++", " ")
                LEMMA = LEMMA.replace("+++", " ")
                LEMMA = LEMMA.replace("++", " ")
                LEMMA = LEMMA.replace("+", " ")

                # Original brackets were \( or \), which cannot be used due to bracket parsing
            if FORM == "*opening_bracket*":
                FORM = "("
            elif FORM == "*closing_bracket*":
                FORM = ")"
            if LEMMA == "*opening_bracket*":
                LEMMA = "("
            elif LEMMA == "*closing_bracket*":
                LEMMA = ")"

                #        XPOS = tag
                #        MISC = defaultdict(lambda: None)
                # Feature Classes called here
                #        UPOS = G_Features(tag, FORM).get_UD_tag()
                #        FEATS = G_Features(tag).get_features()
                #        MISC = defaultdict(lambda: None, {"tag": tag})

            count = 0
            new_nr = 0
            # if " " in FORM:
            if " " in FORM:
                # The token is a multiword token, and needs to be divided
                FORMS = FORM.split(" ")
                if LEMMA is not None:
                    LEMMAS = LEMMA.split(" ")
                else:
                    LEMMAS = []
                XPOS = tag
                UPOS = G_Features(tag, FORM).get_UD_tag()
                FEATS = G_Features(tag, FORM).get_features()
                MISC = defaultdict(lambda: None, {"tag": tag})
                for FORM in FORMS:
                    if len(LEMMAS) > 1:
                        LEMMA = LEMMAS[count]
                    if FORM == FORMS[-1]:
                        MISC = defaultdict(
                            lambda: None,
                            {"tag": tag, "MWEEnd": "Yes"},
                        )
                    self.dg.add_node(
                        {
                            "address": nr,
                            "word": FORM,
                            "lemma": LEMMA,
                            "ctag": UPOS,  # upostag
                            "tag": XPOS,  # xpostag
                            "feats": FEATS,
                            "deps": defaultdict(list),
                            "rel": "_",
                            "misc": MISC,
                        }
                    )
                    nr += 1
                    count += 1
                new_nr = nr

            else:
                if new_nr != 0:
                    XPOS = tag
                    MISC = defaultdict(lambda: None)
                    if LEMMA is not None and " " in LEMMA:
                        # The lemma is a multiword token, which is not allowed
                        MISC = defaultdict(
                            lambda: None,
                            {"tag": tag, "OriginalLemma": LEMMA},
                        )
                        LEMMA = re.sub(" ", "", LEMMA)
                    else:
                        MISC = defaultdict(lambda: None, {"tag": tag})
                    # Feature Classes called here
                    UPOS = G_Features(tag, FORM).get_UD_tag()
                    FEATS = G_Features(tag, FORM).get_features()
                    if FORM not in {"None", None}:
                        self.dg.add_node(
                            {
                                "address": new_nr,  # new_nr,
                                "word": FORM,
                                "lemma": LEMMA,
                                "ctag": UPOS,  # upostag
                                "tag": XPOS,  # xpostag
                                "feats": FEATS,
                                "deps": defaultdict(list),
                                "rel": "_",
                                "misc": MISC,
                            }
                        )
                        nr += 1
                    # new_nr += 1
                else:
                    XPOS = tag
                    MISC = defaultdict(lambda: None)
                    if LEMMA is not None and " " in LEMMA:
                        # The lemma is a multiword token, which is not allowed
                        MISC = defaultdict(
                            lambda: None,
                            {"tag": tag, "OriginalLemma": LEMMA},
                        )
                        LEMMA = re.sub(" ", "", LEMMA)
                    else:
                        MISC = defaultdict(lambda: None, {"tag": tag})
                    # Feature Classes called here
                    UPOS = G_Features(tag, FORM).get_UD_tag()
                    FEATS = G_Features(tag, FORM).get_features()
                    if FORM not in {"None", None}:
                        self.dg.add_node(
                            {
                                "address": nr,  # new_nr,
                                "word": FORM,
                                "lemma": LEMMA,
                                "ctag": UPOS,  # upostag
                                "tag": XPOS,  # xpostag
                                "feats": FEATS,
                                "deps": defaultdict(list),
                                "rel": "_",
                                "misc": MISC,
                            }
                        )
                        nr += 1
                    # new_nr += 1

    def select_graph_heads(self, const, singles, t):
        for i in const:
            # # DEBUG:
            # print(i, t[i], t[i].label(), len(t[i]))
            # input()

            # Catch index referenced sentences in treebank
            if re.match("=\d", t[i].label()[-2:]):  # or t[i].label() == 'CONJP
                clause_index = t[i].label()[-1]
                # re.match('\d', t[i].label()[-2:])
                for j in const + singles:
                    if re.match(f"-{clause_index}", t[j].label()[-2:]):
                        if isinstance(t[j][0], str):
                            t[i].set_id(t[j].id())
                        else:
                            self._select_head(t[i], main_clause=t[j])

            else:
                self._select_head(t[i])

        # fixes subtrees with 1 child but wrong id
        for i in singles:
            if isinstance(t[i][0], Tree) and t[i].id() != t[i][0].id():
                # # DEBUG:
                # print()
                # print('Tree ID:', t[i].id(), 'Child ID:', t[i][0].id())
                # print('Tree:', t[i])
                # # print()
                # print('Child:', t[i][0])

                if re.match("=\d", t[i].label()[-2:]):
                    # print('\nMain Clause indicated\n')
                    clause_index = t[i].label()[-1]
                    # re.match('\d', t[i].label()[-2:])
                    for j in const:
                        if re.match(f"-{clause_index}", t[j].label()[-2:]):
                            self._select_head(t[i][0], main_clause=t[j])
                # else
                else:
                    t[i].set_id(t[i][0].id())

            else:
                self._select_head(t[i])

        # fixes subtrees with 1 child but wrong id
        for i in singles:
            if isinstance(t[i][0], Tree) and t[i].id() != t[i][0].id():
                # # DEBUG:
                # print()
                # print('Tree ID:', t[i].id(), 'Child ID:', t[i][0].id())
                # print('Tree:', t[i])
                # # print()
                # print('Child:', t[i][0])

                if re.match("=\d", t[i].label()[-2:]):
                    # print('\nMain Clause indicated\n')
                    clause_index = t[i].label()[-1]
                    # re.match('\d', t[i].label()[-2:])
                    for j in const:
                        if re.match(f"-{clause_index}", t[j].label()[-2:]):
                            self._select_head(t[i][0], main_clause=t[j])
                # else
                else:
                    t[i].set_id(t[i][0].id())

                # print('Tree ID:', t[i].id(), 'Child ID:', t[i][0].id())

        # runs various subtrees that are likely to have root errors after
        # last block back through head selection
        for i in const:
            if re.match(
                "S0.*",
                t[i].label(),
            ):
                self._select_head(t[i])

    def set_graph_relations(self, const, t):
        for i in const:
            head_tag = t[i].label()
            head_nr = t[i].id()

            for child in t[i]:
                try:
                    mod_tag = child.label()
                except:
                    # print(child)
                    # raise
                    mod_tag = "_"

                try:
                    mod_nr = child.id()
                except:
                    # print("CHILD TYPE: ", type(child), child)
                    mod_nr = "_"

                if child:
                    # NOTE: This is where the root is selected

                    if head_nr == mod_nr:
                        if re.match(
                            "S0.*",
                            head_tag,
                        ):  # todo root phrase types from config
                            self.dg.get_by_address(mod_nr).update(
                                {"head": 0, "rel": "root"}
                            )
                            self.dg.root = self.dg.get_by_address(mod_nr)
                        else:
                            # Unknown dependency relation (things to fix)
                            self.dg.get_by_address(mod_nr).update(
                                {
                                    "head": head_nr,
                                    "rel": self._relation(
                                        mod_tag,
                                        head_tag,
                                        self.dg.get_by_address(mod_nr),
                                    ),
                                }
                            )
                            self.dg.root = self.dg.get_by_address(mod_nr)

                    else:
                        # # DEBUG:
                        # print('head_nr:', head_nr, 'mod_nr:', mod_nr)
                        # print('head_tag', head_tag, 'mod_tag', mod_tag)
                        # print(self.dg.get_by_address(mod_nr))
                        # # input()

                        self.dg.get_by_address(mod_nr).update(
                            {
                                "head": head_nr,
                                "rel": self._relation(
                                    mod_tag,
                                    head_tag,
                                    self.dg.get_by_address(mod_nr),
                                ),
                            }
                        )

                    # # DEBUG:
                    # print(self.dg.get_by_address(mod_nr))
                    # input()

                    if head_nr != mod_nr:
                        self.dg.add_arc(head_nr, mod_nr)

    def fix_graph(self):
        """
        Fixes dependency graph if needed.
        """

        if self.dg.num_roots() != 1:
            # # DEBUG:
            # print(self.dg.to_conllU())
            # input()

            dg_utils.fix_root_relation()

        rel_counts = self.dg.rels()
        ctag_counts = self.dg.ctags()

        if rel_counts["ccomp/xcomp"] > 0:
            dg_utils.fix_ccomp()
        if (
            rel_counts["nsubj"] > 1
            or (rel_counts["nsubj"] == 1 and rel_counts["csubj"] == 1)
            or rel_counts["csubj"] > 1
        ):
            dg_utils.fix_many_subj()

        ##dg_utils.fix_left_right_alignments()

        ## if rel_counts['aux'] > 0:
        ##     dg_utils.fix_aux_tag()
        if rel_counts["acl/advcl"] > 0:
            dg_utils.fix_acl_advcl()
        if rel_counts["advmod"] > 0:
            dg_utils.fix_advmod_tag()
        if rel_counts["aux"] > 0:
            dg_utils.fix_aux_tag_rel()
        if rel_counts["nummod"] > 0:
            dg_utils.fix_nummod_tag()
        if ctag_counts["PROPN"] > 0:
            dg_utils.fix_flatname_dep()
        if rel_counts["mark"] > 0:
            dg_utils.fix_mark_dep()
        if rel_counts["rel"] > 0:
            dg_utils.fix_dep()
        if ctag_counts["AUX"] > 0:
            dg_utils.fix_root_tag()
        dg_utils.fix_head_id_same()
        # if ctag_counts["X"] > 0:
        #    dg_utils.fix_flat_foreign()
        if ctag_counts["CCONJ"] > 0:
            dg_utils.fix_cconj_rel()
        if rel_counts["cop"] > 0:
            dg_utils.fix_cop_head()
            dg_utils.fix_cop_ctag()
        if rel_counts["appos"] > 0:
            dg_utils.fix_appos_lr()
        if rel_counts["cc"] > 0:
            dg_utils.fix_cc_tag()
            dg_utils.fix_cc_rel()
            dg_utils.fix_cc_head()
            dg_utils.fix_zero_dep()
        if rel_counts["conj"] > 0:
            dg_utils.fix_conj_rel()
        if ctag_counts["PUNCT"] > 0:
            dg_utils.fix_punct_rel()
        if rel_counts["acl:relcl"] > 0:
            dg_utils.fix_aclrelcl_rel()
        if rel_counts["punct"] > 0:
            dg_utils.fix_punct_heads()
        if rel_counts["dep"] > 0:
            dg_utils.fix_dep_rel()
        if rel_counts["_"] > 0:
            dg_utils.fix_mwe()
        if ctag_counts["SYM"] > 0:
            dg_utils.fix_sym_feats()
        if rel_counts["case"] > 0:
            dg_utils.fix_case_rel()
        dg_utils.fix_cc_rel()
        dg_utils.fix_head_id_same()
        if self.dg.num_roots() != 1:
            # # DEBUG:
            # print(self.dg.to_conllU())
            # input()

            dg_utils.fix_root_relation()

        # DEBUG:
        # if self.dg.get_by_address(len(self.dg.nodes)-1)['word'] == None:
        #     dg_utils.fix_empty_node()

        # if rel_counts['cop'] > 0:
        #     dg_utils.fix_cop()

    @staticmethod
    def check_left_to_right(dgraph):
        """
        Certain UD relations must always go left-to-right.
        """
        for address in dgraph.addresses():
            cols = dgraph.get_by_address(address)
            if re.match(r"^[1-9][0-9]*-[1-9][0-9]*$", str(cols["address"])):
                continue
            # if DEPREL >= len(cols):
            #     return # this has been already reported in trees()
            # According to the v2 guidelines, apposition should also be left-headed, although the definition of apposition may need to be improved.
            if re.match(r"^(conj|fixed|flat|goeswith|appos)", cols["rel"]):
                ichild = int(cols["address"])
                iparent = int(cols["head"])
                if ichild < iparent:
                    # We must recognize the relation type in the test id so we can manage exceptions for legacy treebanks.
                    # For conj, flat, and fixed the requirement was introduced already before UD 2.2, and all treebanks in UD 2.3 passed it.
                    # For appos and goeswith the requirement was introduced before UD 2.4 and legacy treebanks are allowed to fail it.
                    # testid = "right-to-left-%s" % lspec2ud(cols['rel'])
                    testmessage = (
                        "Line %s: Relation %s must go left-to-right.\nWord form: %s"
                        % (address, cols["rel"], cols["word"])
                    )
                    print(testmessage)

    @staticmethod
    def add_space_after(dgraph):
        """10.03.20
        Fills in Space_after feature in misc column.

        """

        for address in dgraph.addresses():
            if type(address) != str:
                id_to_fix = int(address) - 1
                if dgraph.get_by_address(address)["ctag"] == "PUNCT":
                    if id_to_fix < 0:
                        continue
                    elif dgraph.get_by_address(address)["ctag"] == "„":
                        dgraph.get_by_address(address)["misc"]["SpaceAfter"] = "No"
                    elif dgraph.get_by_address(address)["word"] in {"„", "("}:
                        dgraph.get_by_address(address)["misc"]["SpaceAfter"] = "No"
                    elif dgraph.get_by_address(address)["word"] in {"–", "-"}:
                        # print("fix 1: ", dgraph.get_by_address(address))
                        if dgraph.get_by_address(address + 1)[
                            "ctag"
                        ] == "NUM" or re.match(
                            r"\d+", dgraph.get_by_address(address + 1)["word"]
                        ):
                            dgraph.get_by_address(address)["misc"]["SpaceAfter"] = "No"
                        if dgraph.get_by_address(address - 1)[
                            "ctag"
                        ] == "NUM" or re.match(
                            r"\d+", dgraph.get_by_address(address - 1)["word"]
                        ):
                            dgraph.get_by_address(address - 1)["misc"][
                                "SpaceAfter"
                            ] = "No"
                    elif (
                        dgraph.get_by_address(id_to_fix)["lemma"] in {"„", ":", "|"}
                        or address == "1"
                    ):
                        continue
                    elif dgraph.get_by_address(id_to_fix)["misc"]["MWEEnd"] == "Yes":
                        if dgraph.get_by_address(id_to_fix + 1)["word"] in {
                            ".",
                            ",",
                            "?",
                            "!",
                            "“",
                            ":",
                            ")",
                        }:
                            dgraph.get_by_address(id_to_fix)["misc"][
                                "SpaceAfter"
                            ] = "No"
                        continue
                    elif (
                        dgraph.get_by_address(id_to_fix)["ctag"] != "NUM"
                        and dgraph.get_by_address(id_to_fix + 1)["word"] == "—"
                    ):
                        continue
                    else:
                        # print("fix 2: ", dgraph.get_by_address(id_to_fix))
                        dgraph.get_by_address(id_to_fix)["misc"]["SpaceAfter"] = "No"

        return dgraph

    @staticmethod
    def join_graphs(to_join):
        """
        Takes in a list of UniversalDependencyGraph objects and joins them into
        a single UniversalDependencyGraph object, taking into account correct
        relations and deps.


        Arguments:
            to_join (list): List of dependencyGraphs that are to be joined.
        Returns:
            new_dg (UniversalDependencyGraph): New dependency graph of they
                the joined sentences.

        """
        # DEBUG:
        # for dg in to_join:
        #     print(dg.to_conllU())
        new_dg = to_join[0]
        # print('==NEW==')
        # print(new_dg.to_conllU())
        new_dg.original_ID = [str(dg.original_ID) for dg in to_join]
        #    root_phrases = [dg for dg in to_join if dg.original_phrase_tag == 'IP-MAT']
        #    if len(root_phrases) > 0:
        #        new_dg = root_phrases[0]
        #    if new_dg.original_phrase_tag == 'IP-MAT':
        for node in new_dg.nodes.values():
            if node["head"] == 0:
                new_root = node["address"]
        # TODO: Don't think this method works
        #    else:
        #        for node in to_join[1].nodes.values():
        #            if node['head'] == 0:
        #                new_root = node['address']
        new_id = len(new_dg.nodes)
        for old_dg in to_join[1:]:
            # print('==OLD==')
            # print(old_dg.to_conllU())
            old_new_addresses = {}
            old_root = None
            for node in old_dg.nodes.values():
                if node["head"] == 0:
                    old_root = node["address"]
                old_new_addresses[node["address"]] = new_id
                if node["address"] == None or node["word"] in {"None", None}:
                    continue
                else:
                    node.update({"address": new_id})
                new_id += 1
            for node in old_dg.nodes.values():
                if (
                    node["address"] == 0
                    or node["tag"] == "TOP"
                    or node["word"] in {"None", None}
                ):
                    continue
                if node["head"] == 0:
                    node.update(
                        {"head": new_root, "rel": "conj", "misc": {"OriginalHead": "0"}}
                    )
                    if node["ctag"] == "PUNCT":
                        node.update({"rel": "punct"})
                    # TODO: fix misc, erases previous
                # TODO: get the end-of-sentence punctuation to be dependent on the new root
                elif (
                    node["head"] == old_root
                    #    and node["address"] < node["head"]
                    and node["ctag"] == "PUNCT"
                    and node["address"] + 1 not in old_dg.nodes
                    # and node["address"] + 2 not in old_dg.nodes
                    # and old_dg.get_by_address(node["address"] + 1)["address"] != None
                ):
                    # if node["address"] + 1 in old_dg.nodes:
                    #    node.update({"head": node["address"] - 1})
                    # else:
                    # print(old_dg.get_by_address(node["address"] + 1))
                    # print("node[address]:", node["address"])
                    node.update({"head": new_root})
                else:
                    try:
                        node.update({"head": old_new_addresses[node["head"]]})
                    except KeyError:
                        # print(node)
                        # for x in to_join:
                        #    print(x.plain_text())
                        # print(list(to_join))
                        # print(node["head"])
                        raise

                new_dg.add_node(node)

        # TODO: fix deps:
        # for node in new_dg.nodes.values():
        #     node.update({'deps' : None})
        # for i in range(len(new_dg.nodes)+1):
        #     new_dg.add_arc(new_dg.get_by_address(i)['head'], i)
        # print(new_dg)

        # for address, node in new_dg.nodes.items():
        #    if node['ctag'] == 'PUNCT' and node['rel'] == 'punct' and

        for address, node in list(new_dg.nodes.items()):
            if node["ctag"] == "PUNCT" and node["rel"] == "punct":
                if (
                    node["head"] == new_dg.get_by_address(address - 1)["head"]
                    and address + 1 in new_dg.nodes
                ):
                    new_dg.get_by_address(address).update({"head": address - 1})
                elif (
                    type(
                        new_dg.get_by_address(
                            new_dg.get_by_address(address - 1)["head"]
                        )["head"]
                    )
                    == int
                    and address + 1 in new_dg.nodes
                    and node["head"]
                    < new_dg.get_by_address(new_dg.get_by_address(address - 1)["head"])[
                        "head"
                    ]
                    and node["head"]
                    < new_dg.get_by_address(new_dg.get_by_address(address - 1)["head"])[
                        "address"
                    ]
                ):
                    new_dg.get_by_address(address).update(
                        {
                            "head": new_dg.get_by_address(
                                new_dg.get_by_address(address - 1)["head"]
                            )["address"]
                        }
                    )

        return new_dg


if __name__ == "__main__":
    # main(argv[1:])
    # test_case(sys.argv[1])
    pass
