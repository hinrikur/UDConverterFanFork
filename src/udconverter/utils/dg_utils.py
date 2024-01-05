import re


def fix_aclrelcl_rel(ud_graph: "UniversalDependencyGraph"):
    """
    A specific case fixed, where two nodes are dependent on each other and the former node has the deprel 'acl:relcl'
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if (
            node["rel"] == "acl:relcl"
            and node["head"] == address + 2
            and ud_graph.get_by_address(address + 2)["head"] == address
        ):
            if ud_graph.get_by_address(address - 4)["head"] == 9:
                ud_graph.get_by_address(address).update({"head": address - 4})


def fix_punct_tag(ud_graph: "UniversalDependencyGraph"):
    """
    A word with the deprel 'punct' must be tagged PUNCT
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["rel"] == "punct" and node["ctag"] != "PUNCT":
            ud_graph.get_by_address(address).update({"ctag": "PUNCT"})


def fix_punct_rel(ud_graph: "UniversalDependencyGraph"):
    """
    A word with the tag PUNCT must have the deprel 'punct'
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["ctag"] == "PUNCT" and node["rel"] != "punct":
            ud_graph.get_by_address(address).update({"rel": "punct"})

        # A 'punct' node should never be the root and shouldn't have any dependents
        elif node["ctag"] == "PUNCT" and node["rel"] == "punct" and node["head"] == 0:
            if (
                ud_graph.get_by_address(address + 1)["head"] == address
                and ud_graph.get_by_address(address + 2)["head"] == address
            ):
                ud_graph.get_by_address(address).update({"head": address + 2})
                ud_graph.get_by_address(address + 1).update({"head": address + 2})
                ud_graph.get_by_address(address + 2).update({"head": 0, "rel": "root"})
        elif (
            node["rel"] == "punct"
            and node["ctag"] != "NOUN"
            and ud_graph.get_by_address(node["head"])["rel"] == "conj"
        ):
            ud_graph.get_by_address(address).update({"rel": "obl"})


def fix_flatname_dep(ud_graph: "UniversalDependencyGraph"):
    """
    Finds and fixes a fixed phrase, flat:name
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if (
            node["ctag"] == "PROPN"
            and ud_graph.get_by_address(address - 1)["ctag"] == "PROPN"
            and node["head"] == address - 1
            and node["rel"] != "flat:name"
        ):
            ud_graph.get_by_address(address).update({"rel": "flat:name"})
            # if ud_graph.get_by_address(address+1)['ctag'] == 'PROPN' and ud_graph.get_by_address(address+1)['rel'] == 'dep' and ud_graph.get_by_address(address+1)['head'] == node['head']:
            #    ud_graph.get_by_address(address+1).update({'rel': 'flat:name'})


def fix_mark_dep(ud_graph: "UniversalDependencyGraph"):
    """
    Finds a fixed phrase and fixes its deprel
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if (
            node["rel"] == "mark"
            and node["ctag"] == "SCONJ"
            and ud_graph.get_by_address(address + 1)["rel"] == "mark"
            and ud_graph.get_by_address(address + 1)["ctag"] == "SCONJ"
        ):
            ud_graph.get_by_address(address + 1).update({"rel": "fixed"})
            if ud_graph.get_by_address(address + 1)["head"] != address:
                ud_graph.get_by_address(address + 1).update({"head": address})
            if (
                ud_graph.get_by_address(address + 2)["rel"] == "mark"
                and ud_graph.get_by_address(address + 2)["ctag"] == "SCONJ"
                and ud_graph.get_by_address(address + 2)["head"] == address + 1
            ):
                ud_graph.get_by_address(address + 2).update({"rel": "fixed"})
                ud_graph.get_by_address(address + 2).update({"head": address})
        elif (
            node["rel"] == "mark"
            and node["ctag"] == "SCONJ"
            and node["word"] == "sem"
            and ud_graph.get_by_address(address - 1)["word"] == "svo"
        ):
            ud_graph.get_by_address(address).update({"head": address - 1})
            ud_graph.get_by_address(address).update({"rel": "fixed"})
        elif (
            node["rel"] == "mark"
            and ud_graph.get_by_address(address - 1)["head"] == address
            and ud_graph.get_by_address(address - 2)["head"] == address
            and node["ctag"] == "SCONJ"
        ):
            ud_graph.get_by_address(address - 2).update(
                {"head": node["head"], "rel": "mark"}
            )
            ud_graph.get_by_address(address - 1).update(
                {"head": address - 2, "rel": "fixed"}
            )
            ud_graph.get_by_address(address).update(
                {"head": address - 2, "rel": "fixed"}
            )
            if ud_graph.get_by_address(address - 3)["head"] == address:
                ud_graph.get_by_address(address - 3).update({"head": node["head"]})
        elif (
            node["rel"] == "mark"
            and ud_graph.get_by_address(address + 1)["head"] == address
            and ud_graph.get_by_address(address + 1)["ctag"] == "ADP"
        ):
            ud_graph.get_by_address(address + 1).update({"rel": "fixed"})


def fix_dep(ud_graph: "UniversalDependencyGraph"):
    """
    Fixes the second noun's deprel in a CONJP
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["rel"] == "dep":
            if (
                ud_graph.get_by_address(address - 1)["ctag"] == "CCONJ"
                and ud_graph.get_by_address(address - 2)["ctag"] == r"N[PRS-NADG]"
            ):
                ud_graph.get_by_address(address).update({"rel": "conj"})


def fix_root_tag(ud_graph: "UniversalDependencyGraph"):
    """
    Changes a verb's tag from AUX to VERB if it is the root of the sentence
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["rel"] == "root" and node["ctag"] == "AUX":
            ud_graph.get_by_address(address).update({"ctag": "VERB"})


def fix_head_id_same(ud_graph: "UniversalDependencyGraph"):
    """
    Changes a node's head if it is dependent on itself
    """

    try:
        items = list(ud_graph.nodes.items())
        for address, node in items:
            if node["address"] == node["head"]:
                if address != 1:
                    if (
                        node["rel"] == "conj"
                        and node["ctag"] == "NOUN"
                        and ud_graph.get_by_address(address - 1)["ctag"] == "ADJ"
                        and ud_graph.get_by_address(address - 1)["rel"] == "obl"
                    ):
                        ud_graph.get_by_address(address).update(
                            {
                                "head": ud_graph.get_by_address(address - 1)["head"],
                                "rel": ud_graph.get_by_address(address - 1)["rel"],
                            }
                        )
                        ud_graph.get_by_address(address - 1).update(
                            {"head": address, "rel": "amod"}
                        )
                    elif (
                        address - 12 in ud_graph.nodes
                        and ud_graph.get_by_address(address - 12)["ctag"] == "VERB"
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 12})
                    elif (
                        address - 4 in ud_graph.nodes
                        and ud_graph.get_by_address(address - 4)["ctag"] == "VERB"
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 4})
                    elif (
                        address - 3 in ud_graph.nodes
                        and ud_graph.get_by_address(address - 3)["ctag"] == "VERB"
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 3})
                    elif (
                        address - 2 in ud_graph.nodes
                        and ud_graph.get_by_address(address - 2)["rel"] == "root"
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 2})
                    elif (
                        address - 2 in ud_graph.nodes
                        and ud_graph.get_by_address(address - 2)["ctag"] == "VERB"
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 2})
                    elif (
                        address - 1 in ud_graph.nodes
                        and ud_graph.get_by_address(address - 1)["ctag"] == "VERB"
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 1})
                    elif (
                        address - 1 in ud_graph.nodes
                        and ud_graph.get_by_address(address - 1)["ctag"] == "PART"
                        and ud_graph.get_by_address(address - 1)["rel"] == "root"
                        and node["rel"] == "xcomp"
                    ):
                        ud_graph.get_by_address(address - 1).update(
                            {"head": address, "rel": "mark"}
                        )
                        ud_graph.get_by_address(address).update(
                            {"head": 0, "rel": "root"}
                        )
                        if (
                            ud_graph.get_by_address(address + 4)["rel"] == "punct"
                            and ud_graph.get_by_address(address + 4)["head"]
                            == address - 1
                        ):
                            ud_graph.get_by_address(address + 4).update(
                                {"head": address}
                            )
                    elif (
                        address - 1 in ud_graph.nodes
                        and node["rel"] == "conj"
                        and ud_graph.get_by_address(address - 1)["head"] == address
                        and ud_graph.get_by_address(address - 2)["head"] == address
                        and ud_graph.get_by_address(address - 3)["head"] == address
                        and address > ud_graph.root_address()
                    ):
                        ud_graph.get_by_address(address).update(
                            {"head": ud_graph.root_address()}
                        )
                    elif (
                        address - 4 in ud_graph.nodes
                        and ud_graph.get_by_address(address - 4)["rel"] == "conj"
                        and node["rel"] == "acl:relcl"
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 4})
                    elif (
                        node["rel"] == "acl:relcl"
                        and ud_graph.get_by_address(address - 4)["rel"] == "xcomp"
                        and ud_graph.get_by_address(address - 4)["ctag"] == "SCONJ"
                    ):
                        ud_graph.get_by_address(address).update(
                            {
                                "head": ud_graph.get_by_address(address - 4)["head"],
                                "rel": "xcomp",
                            }
                        )
                        ud_graph.get_by_address(address - 4).update(
                            {"head": address, "rel": "mark"}
                        )
                        if ud_graph.get_by_address(address - 5)["head"] == address - 5:
                            ud_graph.get_by_address(address - 5).update(
                                {"head": address}
                            )
                    elif (
                        node["rel"] == "acl:relcl"
                        and ud_graph.get_by_address(address - 2)["rel"] == "dep"
                        and ud_graph.get_by_address(address - 2)["head"]
                        == ud_graph.root_address()
                        and ud_graph.get_by_address(address - 2)["ctag"] == "PRON"
                    ):
                        ud_graph.get_by_address(address).update(
                            {"head": ud_graph.root_address(), "rel": "obl"}
                        )
                        ud_graph.get_by_address(address - 2).update(
                            {"head": address, "rel": "nmod"}
                        )
                    elif (
                        node["rel"] == "conj"
                        and ud_graph.get_by_address(address - 1)["head"] == address
                        and ud_graph.get_by_address(address - 2)["lemma"] == "um"
                        and ud_graph.get_by_address(address - 2)["ctag"] == "ADV"
                        and ud_graph.get_by_address(address - 2)["head"] == address - 4
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 4})
                        ud_graph.get_by_address(address - 2).update({"head": address})
                        ud_graph.get_by_address(address - 3).update({"head": address})
                else:
                    if (
                        address + 1 in ud_graph.nodes.items()
                        and ud_graph.get_by_address(address + 1)["ctag"] == "VERB"
                    ):
                        ud_graph.get_by_address(address).update({"head": address + 1})
                    elif (
                        address + 2 in ud_graph.nodes.items()
                        and ud_graph.get_by_address(address + 2)["word"] != None
                        and ud_graph.get_by_address(address + 2)["ctag"] == "VERB"
                    ):
                        ud_graph.get_by_address(address).update({"head": address + 2})
                    elif (
                        address + 3 in ud_graph.nodes.items()
                        and ud_graph.get_by_address(address + 3)["word"] != None
                        and ud_graph.get_by_address(address + 3)["ctag"] == "VERB"
                    ):
                        ud_graph.get_by_address(address).update({"head": address + 3})
                    elif (
                        address + 4 in ud_graph.nodes.items()
                        and ud_graph.get_by_address(address + 4)["word"] != None
                        and ud_graph.get_by_address(address + 4)["ctag"] == "VERB"
                    ):
                        ud_graph.get_by_address(address).update({"head": address + 4})
    except RuntimeError:
        # pass
        # print(ud_graph.nodes.items())
        raise


def fix_flat_foreign(ud_graph: "UniversalDependencyGraph"):
    """
    Relations of a foreign multi-word phrase fixed
    """

    try:
        items = list(ud_graph.nodes.items())
        for address, node in items:
            if node["ctag"] == "X":
                if (
                    address + 1 in ud_graph.nodes
                    and ud_graph.get_by_address(address + 1)["head"] == address
                    and ud_graph.get_by_address(address + 1)["ctag"] == "PROPN"
                ):
                    ud_graph.get_by_address(address + 1).update({"rel": "flat:foreign"})
                if node["head"] > address:
                    ud_graph.get_by_address(address).update({"rel": "dep"})
                if (
                    address - 1 in ud_graph.nodes
                    and ud_graph.get_by_address(address - 1)["head"] == address
                    and ud_graph.get_by_address(address - 1)["ctag"] == "ADP"
                ):
                    ud_graph.get_by_address(address - 1).update({"rel": "dep"})

    except RuntimeError:
        # pass
        # print(ud_graph.nodes.items())
        raise


def fix_left_right_alignments(ud_graph: "UniversalDependencyGraph"):
    """
    Certain relations must always go left-to-right
    TODO: not currently in use, 'check_left_to_right' replaces this?
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["rel"] == "conj" and node["head"] > address:
            if (
                ud_graph.get_by_address(address - 5)["rel"] == "nsubj"
                and ud_graph.get_by_address(address - 5)["head"] == node["head"]
            ):
                ud_graph.get_by_address(address).update({"head": address - 5})
            elif (
                ud_graph.get_by_address(address - 9)["rel"] == "nsubj"
                and ud_graph.get_by_address(address - 5)["head"] == node["head"]
            ):
                ud_graph.get_by_address(address).update({"head": address - 9})


def fix_appos_lr(ud_graph: "UniversalDependencyGraph"):
    """
    The deprel 'appos' can only go left-to-right
    """

    for (
        address,
        node,
    ) in ud_graph.nodes.items():
        if (
            ud_graph.get_by_address(address)["rel"] == "appos"
            and ud_graph.get_by_address(address)["head"] > address
        ):
            head_address = ud_graph.get_by_address(address)["head"]
            if ud_graph.get_by_address(head_address)["ctag"] in {"VERB", "AUX"}:
                ud_graph.get_by_address(address).update({"rel": "obl"})
            elif ud_graph.get_by_address(head_address)["ctag"] in {
                "NOUN",
                "PROPN",
                "PRON",
                "ADJ",
            }:
                ud_graph.get_by_address(address).update({"rel": "nmod"})


def fix_cop_head(ud_graph: "UniversalDependencyGraph"):
    """
    A copula cannot be head. If so, the dependents' head addresses are changed to the head's head address
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["head"] != "_":
            headaddress = node["head"]
            if ud_graph.get_by_address(headaddress)["rel"] == "cop":
                head_headaddress = ud_graph.get_by_address(headaddress)["head"]
                ud_graph.get_by_address(address).update({"head": head_headaddress})
        #  if ud_graph.get_by_address(headaddress)["ctag"] == "SCONJ":
        #      ud_graph.get_by_address(address).update(
        #          {"head": ud_graph.get_by_address(address - 1)["head"]}
        #      )


def fix_cop_ctag(ud_graph: "UniversalDependencyGraph"):
    """
    A copula has to be tagged as "AUX", "PRON" or "DET"
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["rel"] == "cop" and node["ctag"] == "VERB":
            ud_graph.get_by_address(address).update({"ctag": "AUX"})


def fix_zero_dep(ud_graph: "UniversalDependencyGraph"):
    """
    Fixes root nodes which don't have the deprel 'root'
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["rel"] != "root" and node["head"] == 0:
            if (
                node["rel"] == "cc"
                and ud_graph.get_by_address(address + 1)["head"] == 0
                and ud_graph.get_by_address(address + 3)["head"] == 0
            ):
                if (
                    ud_graph.get_by_address(address + 1)["rel"] == "advmod"
                    and ud_graph.get_by_address(address + 3)["rel"] == "obl"
                ):
                    ud_graph.get_by_address(address).update({"head": address + 1})
                    ud_graph.get_by_address(address + 1).update({"head": address - 1})
                    ud_graph.get_by_address(address + 3).update({"head": address + 1})


def fix_many_subj(ud_graph: "UniversalDependencyGraph"):
    """
    If subjects of a verb are more than one, the ones following the first subject get the deprel 'obl'
    """

    nsubj = ud_graph.num_subj()

    if nsubj:
        count = 0
        items = list(ud_graph.nodes.items())
        for address, node in items:
            if node["word"] in nsubj:
                if count == 0:
                    count += 1
                elif count > 0:
                    ud_graph.get_by_address(address).update({"rel": "obl"})


def fix_dep_rel(ud_graph: "UniversalDependencyGraph"):
    """
    Fixes nodes with the deprel 'dep', which is used when no other deprel applies
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["rel"] == "dep" and node["head"] == address:
            ud_graph.get_by_address(address).update({"head": address - 1})
        elif node["rel"] == "dep" and node["head"] == 0:
            ud_graph.get_by_address(address).update({"rel": "root"})


def fix_case_rel(ud_graph: "UniversalDependencyGraph"):
    """
    Fixes nodes with the deprel 'case' which are part of the fixed phrase 'frá og með'
    TODO: currently not in use
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if (
            node["rel"] == "case"
            and ud_graph.get_by_address(address + 1)["head"] == address
            and ud_graph.get_by_address(address + 2)["head"] == address
        ):
            if node["lemma"] == "frá" and ud_graph.get_by_address(address + 2) == "með":
                ud_graph.get_by_address(address + 1).update({"rel": "fixed"})
                ud_graph.get_by_address(address + 2).update({"rel": "fixed"})
        elif (
            node["rel"] == "case"
            and ud_graph.get_by_address(address + 1)["head"] == address
            and ud_graph.get_by_address(address + 1)["rel"] == "case"
        ):
            ud_graph.get_by_address(address + 1).update({"rel": "fixed"})


def fix_mwe(ud_graph: "UniversalDependencyGraph"):
    """
    Fixes nodes within MWEs which don't have a dependency
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if type(address) is int and node["rel"] == "_" and node["head"] == "_":
            if ud_graph.get_by_address(address - 1)[
                "head"
            ] != "_" and ud_graph.get_by_address(address - 1)["rel"] not in {
                "fixed",
                "flat",
            }:
                ud_graph.get_by_address(address).update({"head": address - 1})
            elif ud_graph.get_by_address(address - 2)[
                "head"
            ] != "_" and ud_graph.get_by_address(address - 2)["rel"] not in {
                "fixed",
                "flat",
            }:
                ud_graph.get_by_address(address).update({"head": address - 2})
            elif ud_graph.get_by_address(address - 3)[
                "head"
            ] != "_" and ud_graph.get_by_address(address - 3)["rel"] not in {
                "fixed",
                "flat",
            }:
                ud_graph.get_by_address(address).update({"head": address - 3})
            elif ud_graph.get_by_address(address - 4)[
                "head"
            ] != "_" and ud_graph.get_by_address(address - 4)["rel"] not in {
                "fixed",
                "flat",
            }:
                ud_graph.get_by_address(address).update({"head": address - 4})
            elif ud_graph.get_by_address(address - 5)[
                "head"
            ] != "_" and ud_graph.get_by_address(address - 5)["rel"] not in {
                "fixed",
                "flat",
            }:
                ud_graph.get_by_address(address).update({"head": address - 5})
            elif ud_graph.get_by_address(address - 6)[
                "head"
            ] != "_" and ud_graph.get_by_address(address - 6)["rel"] not in {
                "fixed",
                "flat",
            }:
                ud_graph.get_by_address(address).update({"head": address - 6})

            orig_tag = node["tag"].split("_")[0]

            if orig_tag in {
                "ártal",
                "dagsafs",
                "dagsföst",
                "tímapunktur",
                "tími",
                "tímapunkturafs",
                "person",
                "sérnafn",
                "entity",
                "fyrirtæki",
                "gata",
                "no",
                "prósenta",
                "tala",
                "töl",
                "mælieining",
            }:
                ud_graph.get_by_address(address).update({"rel": "flat"})
            elif orig_tag == "foreign":
                ud_graph.get_by_address(address).update({"rel": "flat:foreign"})
            elif orig_tag in {"ao", "eo", "fs", "fn", "pfn", "abfn", "st"}:
                ud_graph.get_by_address(address).update({"rel": "fixed"})


def fix_sym_feats(ud_graph: "UniversalDependencyGraph"):
    """
    Fixes features of nodes with the ctag 'SYM'
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["ctag"] == "SYM":
            ud_graph.get_by_address(address).update({"feats": None})


def fix_root_relation(ud_graph: "UniversalDependencyGraph"):
    """09.03.20
    Fixes buggy root relations in filled out sentence graph by checking
    number of root relations and verb POS tags.

    # TODO: Finish implementation / documentation
    """

    # If there is no root in sentence
    # print('\n@ _fix_root_relation()\n')
    if ud_graph.num_roots() < 1:
        # NOTE: catches sentences with only one word and marks it as root
        if len(ud_graph.nodes) == 2:
            ud_graph.get_by_address(1).update({"head": 0, "rel": "root"})

        # NOTE: when no verb in sentence and no root
        if ud_graph.num_verbs() == 0:
            # print('No root relation found in sentence.')
            items = list(ud_graph.nodes.items())
            for address, node in items:
                if type(address) != str:
                    if address == node["head"]:
                        # # DEBUG:
                        # print('Node to fix:')
                        # print(ud_graph.get_by_address(address))
                        # print()

                        ud_graph.get_by_address(address).update(
                            {"head": 0, "rel": "root"}
                        )
                    elif (
                        node["head"] == address - 1
                        and ud_graph.get_by_address(address - 1)["head"] == address
                    ):
                        ud_graph.get_by_address(address).update(
                            {"head": 0, "rel": "root"}
                        )

                    elif (
                        node["head"] == address - 3
                        and ud_graph.get_by_address(address - 3)["head"] == address
                    ):
                        ud_graph.get_by_address(address).update(
                            {"head": 0, "rel": "root"}
                        )

        # NOTE: when one verb in sent but no root
        elif ud_graph.num_verbs() == 1:
            # TODO: Hér þarf sögnin að vera valin sem rót en vensl annarra
            #       orða við sögnina haldist rétt / séu lagfærð í leiðinni.
            # pass
            items = list(ud_graph.nodes.items())
            for address, node in items:
                # print(address, node['head'])
                if address == node["head"]:
                    ud_graph.get_by_address(address).update({"head": 0, "rel": "root"})

                elif (
                    node["head"] == address - 1
                    and ud_graph.get_by_address(address - 1)["head"] == address
                ):
                    ud_graph.get_by_address(address).update({"head": 0, "rel": "root"})

        # NOTE: when more than one verb in sent but no root
        #       E.g. "Má ég klappa honum aftur á eftir?", where Klappa
        #       should get the root relation but not "Má"
        elif ud_graph.num_verbs() > 1:
            # TODO: Passa að rétt sögn (umsögn aðalsetningar) sé valin sem
            #       rót og ekki aðrar sagnir.
            items = list(ud_graph.nodes.items())
            for address, node in items:
                # print(address, node['head'])
                if address == node["head"]:
                    # # DEBUG:
                    # print('Node to fix:')
                    # print(ud_graph.get_by_address(address))
                    # print()

                    ud_graph.get_by_address(address).update({"head": 0, "rel": "root"})
                elif (
                    node["head"] == address - 1
                    and ud_graph.get_by_address(address - 1)["head"] == address
                ):
                    ud_graph.get_by_address(address).update({"head": 0, "rel": "root"})
                elif (
                    node["rel"] == "ccomp"
                    and node["head"] == address - 4
                    and ud_graph.get_by_address(address - 4)["rel"] == "mark"
                ):
                    ud_graph.get_by_address(address).update({"head": 0, "rel": "root"})
                elif (
                    node["rel"] == "ccomp"
                    and node["head"] == address - 3
                    and ud_graph.get_by_address(address - 3)["head"] == address
                ):
                    ud_graph.get_by_address(address).update({"head": 0, "rel": "root"})
                elif (
                    node["rel"] == "ccomp"
                    and node["head"] == address - 2
                    and ud_graph.get_by_address(address - 2)["head"] == address
                ):
                    ud_graph.get_by_address(address).update({"head": 0, "rel": "root"})
                elif (
                    node["rel"] == "conj"
                    and node["head"] == address - 3
                    and (
                        ud_graph.get_by_address(address - 3)["head"] == address
                        or ud_graph.get_by_address(address - 3)["rel"] == "nmod"
                    )
                ):
                    ud_graph.get_by_address(address).update({"head": 0, "rel": "root"})
                elif (
                    node["rel"] == "ccomp"
                    and node["head"] == address - 10
                    and ud_graph.get_by_address(address - 10)["head"] == address
                ):
                    ud_graph.get_by_address(address).update({"head": 0, "rel": "root"})

                # elif (     # TODO: virkar ekki, reynt fyrir 00420.gld
                #    node["head"] == 1
                #    and node["rel"] == "conj"
                #    and node["ctag"] == "VERB"
                # ):
                #    ud_graph.get_by_address(address).update(
                #        {"head": 0, "rel": "root"}
                #    )
            pass

    # If there is more than one root in sentence
    elif ud_graph.num_roots() > 1:
        # # DEBUG:
        # print('\nNo. of verbs in sentence:\n', ud_graph.num_verbs())
        # print()

        if ud_graph.num_verbs() == 1:
            pass


def fix_ccomp(ud_graph: "UniversalDependencyGraph"):
    """
    finds all nodes in graph with the relation 'ccomp/xcomp' and fixes them

    checks where ccomp can appear and should leave only xcomp nodes

    Returns:
        None

    """
    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["rel"] == "ccomp/xcomp":
            ud_graph.get_by_address(address).update({"rel": "xcomp"})
            # # DEBUG:
            # print('\nccomp/xcomp error node:')
            # print(address, node)

            for other_address, other_node in ud_graph.nodes.items():
                # check if nsubj node has ccomp/xcomp node as head
                if other_node["head"] == address and other_node["rel"] == "nsubj":
                    # # DEBUG:
                    # print('\n=> check for nsubj relation to error node\n')
                    # print(other_address, other_node)
                    # input()

                    ud_graph.get_by_address(address).update({"rel": "ccomp"})
                elif other_node["address"] == node["head"] and ud_graph.get_by_address(
                    other_node["head"]
                )["ctag"] in {
                    "AUX",
                    "VERB",
                }:
                    # checks if error node head is verb and whether that verb has a nsubj node attached
                    # NOTE: likely be too greedy
                    for (
                        other_other_address,
                        other_other_node,
                    ) in ud_graph.nodes.items():
                        if (
                            other_other_node["head"] == other_node["head"]
                            and other_other_node["rel"] == "nsubj"
                        ):
                            # # DEBUG:
                            # print('\n=> check if error node head is verb and verb has nsubj\n')
                            # print(other_address, other_node)
                            # print(other_other_address, other_other_node)
                            # input()

                            ud_graph.get_by_address(address).update({"rel": "ccomp"})
                elif (
                    other_node["head"] == node["head"] and other_node["rel"] == "nsubj"
                ):
                    if other_node["ctag"] == "PRON" and re.search(
                        "(-A|-D|-G)", other_node["tag"]
                    ):
                        # accusative and dative pronouns as subject may indicate no real subject, thus xcomp relation
                        # print('\n=> MAYBE NOT TOO GREEDY? (xcomp)')
                        # ud_graph.get_by_address(address).update({'rel': 'xcomp'})
                        continue
                    else:
                        # This chould also be ccomp but is too greedy
                        # print('\n=> TOO GREEDY\n')
                        ud_graph.get_by_address(address).update({"rel": "ccomp"})
                        # continue

            # else:
            #     print('\n=> NO FIX\n')

            # else:
            #     ud_graph.get_by_address(address).update({'rel': 'xcomp'})


def fix_cop(ud_graph: "UniversalDependencyGraph"):
    """
    Fixes a copula verb's argument
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if (
            node["rel"] == "cop"
            and ud_graph.get_by_address(address + 1)["word"] != None
        ):
            ud_graph.get_by_address(address + 1).update({"rel": "root"})


def fix_aux_tag_rel(ud_graph: "UniversalDependencyGraph"):
    """
    UD convention
    Fixes UPOS tag for verbs that have relation 'aux' but not UPOS tag AUX. Also makes sure that verbs with the relation 'aux' do not have dependencies.
    """

    for address, node in list(ud_graph.nodes.items()):
        if (
            node["rel"] == "aux"
            and node["tag"] != "AUX"
            and node["ctag"] != "AUX"
            and node["ctag"] != "RD"
        ):
            ud_graph.get_by_address(address).update({"ctag": "AUX"})
        if (
            node["rel"] in {"aux", "dep"}
            and ud_graph.get_by_address(node["head"])["rel"] == "aux"
        ):
            ud_graph.get_by_address(address).update(
                {"head": ud_graph.get_by_address(node["head"])["head"]}
            )
        if (
            node["rel"] == "aux"
            and ud_graph.get_by_address(address + 1)["head"] == address
        ):
            if (
                ud_graph.get_by_address(address - 2)["rel"] == "cc"
                and node["head"] < address
            ):
                ud_graph.get_by_address(address).update({"rel": "conj", "ctag": "VERB"})
            elif ud_graph.get_by_address(address + 1)["rel"] in {"aux", "cop"}:
                ud_graph.get_by_address(address + 1).update({"head": node["head"]})
            elif ud_graph.get_by_address(address + 1)["rel"] == "advmod":
                ud_graph.get_by_address(address + 1).update({"head": node["head"]})
                if (
                    ud_graph.get_by_address(address + 2)["head"] == address
                    and ud_graph.get_by_address(address + 2)["rel"] == "advmod"
                ):
                    ud_graph.get_by_address(address + 2).update({"head": node["head"]})
        elif (
            node["rel"] == "aux"
            and ud_graph.get_by_address(address + 2)["head"] == address
        ):
            ud_graph.get_by_address(address + 2).update({"head": node["head"]})
        elif (
            node["rel"] == "aux"
            and ud_graph.get_by_address(address - 1)["head"] == address
        ):
            ud_graph.get_by_address(address - 1).update({"head": node["head"]})
        if (
            node["rel"] == "aux"
            and ud_graph.get_by_address(address + 4)["head"] == address
        ):
            ud_graph.get_by_address(address + 4).update({"head": node["head"]})


def fix_acl_advcl(ud_graph: "UniversalDependencyGraph"):
    """
    finds all nodes in graph with the relation 'acl/advcl' and fixes them

    checks where ccomp can appear and should leave only xcomp nodes

    Returns:
        None

    """
    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["rel"] == "acl/advcl":
            # If the head is a verb
            if ud_graph.get_by_address(node["head"])["ctag"] == "VERB":
                # # DEBUG
                # print('=> Head is verb\n', ud_graph.get_by_address(address))

                ud_graph.get_by_address(address).update({"rel": "advcl"})
            # If the head has a cop attached
            elif ud_graph.get_by_address(node["head"])["ctag"] in {
                "NOUN",
                "PROPN",
                "PRON",
                "ADJ",
            }:
                # # DEBUG
                # print('=> Head seems to be nominal\n', ud_graph.get_by_address(address))

                for other_address, other_node in ud_graph.nodes.items():
                    if (
                        other_node["head"] == node["head"]
                        and other_node["rel"] == "cop"
                    ):
                        ud_graph.get_by_address(address).update({"rel": "advcl"})
                    # Should have acl relation if not caught above
                    else:
                        ud_graph.get_by_address(address).update({"rel": "acl"})
            # All cases not yet caught ~should~ have relation acl
            else:
                ud_graph.get_by_address(address).update({"rel": "acl"})
        else:
            continue


def fix_punct_heads(ud_graph: "UniversalDependencyGraph"):
    """
    Fixes the head of a punctuation mark. End-of-sentence punctuation should always be dependent on the sentence's root
    """
    try:
        items = list(ud_graph.nodes.items())
        for address, node in items:
            if node["ctag"] == "PUNCT":
                if address + 1 not in ud_graph.nodes:
                    if (
                        ud_graph.root_address() != None
                        and address > ud_graph.root_address()
                    ):
                        ud_graph.get_by_address(address).update(
                            {"head": ud_graph.root_address()}
                        )
                    else:
                        ud_graph.get_by_address(address).update(
                            {"head": ud_graph.get_by_address(address - 1)["head"]}
                        )

                elif (
                    address + 1 in ud_graph.nodes
                    and ud_graph.get_by_address(address + 1)["rel"] == "conj"
                ):
                    ud_graph.get_by_address(address).update({"head": address + 1})

                elif address != 1:
                    if (
                        address - 1 in ud_graph.nodes
                        and ud_graph.get_by_address(address - 1)["head"] == address
                    ):
                        if node["head"] == address - 1:
                            ud_graph.get_by_address(address - 1).update(
                                {"head": address - 2}
                            )
                        ud_graph.get_by_address(address - 1).update(
                            {"head": node["head"]}
                        )
                    elif (
                        address - 1 in ud_graph.nodes
                        and ud_graph.get_by_address(address - 1)["head"] != "_"
                        and node["head"] <= ud_graph.get_by_address(address - 1)["head"]
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 1})
                    elif (
                        address - 1 in ud_graph.nodes
                        and ud_graph.get_by_address(address - 1)["rel"] == "conj"
                        and type(ud_graph.get_by_address(address - 1)["head"]) == int
                        and node["head"] > ud_graph.get_by_address(address - 1)["head"]
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 1})
                    elif (
                        address - 2 in ud_graph.nodes
                        and address - 1 in ud_graph.nodes
                        and node["head"] == address - 1
                    ):
                        if ud_graph.get_by_address(address - 1)["head"] == address:
                            ud_graph.get_by_address(address - 1).update(
                                {"head": address - 2}
                            )
                    elif (
                        address - 2 in ud_graph.nodes
                        and address - 1 in ud_graph.nodes
                        and ud_graph.get_by_address(address - 2)["rel"] == "advcl"
                        and node["head"] > ud_graph.get_by_address(address - 2)["head"]
                        and ud_graph.get_by_address(address - 1)["head"] == address - 2
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 1})
                    elif (
                        address + 2 in ud_graph.nodes
                        and address - 1 in ud_graph.nodes
                        and ud_graph.get_by_address(address + 2)["head"] == address - 1
                        and ud_graph.get_by_address(address - 1)["rel"] == "amod"
                        and ud_graph.get_by_address(address - 1)["head"] <= node["head"]
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 1})
                    elif (
                        address + 2 in ud_graph.nodes
                        and address - 1 in ud_graph.nodes
                        and ud_graph.get_by_address(address + 2)["head"] != "_"
                        and ud_graph.get_by_address(address - 1)["rel"] == "amod"
                        and ud_graph.get_by_address(address - 1)["head"] <= node["head"]
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 1})
                    elif (
                        address + 2 in ud_graph.nodes
                        and address - 1 in ud_graph.nodes
                        and ud_graph.get_by_address(address + 2)["head"] == address - 1
                        and node["head"] < address - 1
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 1})
                    elif (
                        address + 1 in ud_graph.nodes
                        and address - 1 in ud_graph.nodes
                        and node["head"] > address
                        and ud_graph.get_by_address(address + 1)["head"] < address + 1
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 1})
                    elif (
                        address + 1 in ud_graph.nodes
                        and address - 1 in ud_graph.nodes
                        and node["head"] < address - 1
                        and ud_graph.get_by_address(address + 1)["head"] == address - 1
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 1})

                if node["head"] == 0:
                    # If the punctuation is the root of the sentence, which is not allowed
                    for otheraddress, othernode in ud_graph.nodes.items():
                        if othernode["head"] == address:
                            ud_graph.get_by_address(otheraddress).update(
                                {"head": address + 1}
                            )
                        ud_graph.get_by_address(address).update({"head": address + 1})

                if node["rel"] != "punct":
                    ud_graph.get_by_address(address).update({"rel": "punct"})
            elif node["rel"] == "punct" and node["ctag"] != "PUNCT":
                if node["ctag"] == "NOUN":
                    ud_graph.get_by_address(address).update({"rel": "nsubj"})
                else:
                    ud_graph.get_by_address(address).update({"ctag": "punct"})

    except RuntimeError:
        # print(node)
        raise


def fix_empty_node(ud_graph: "UniversalDependencyGraph"):
    """
    For debug cases only
    """
    last_index = len(ud_graph.nodes) - 1
    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["head"] == last_index:
            node["head"] = ud_graph.get_by_address(last_index)["head"]
    del ud_graph.nodes[last_index]


def fix_advmod_tag(ud_graph: "UniversalDependencyGraph"):
    """
    A word with the deprel 'advmod' must be tagged ADV
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["rel"] == "advmod" and node["ctag"] != "ADV":
            ud_graph.get_by_address(address).update({"ctag": "ADV"})
        elif node["rel"] == "det" and node["ctag"] == "ADV":
            ud_graph.get_by_address(address).update({"rel": "advmod"})


def fix_nummod_tag(ud_graph: "UniversalDependencyGraph"):
    """
    A word with the deprel 'nummod' must be tagged NUM
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["rel"] == "nummod" and node["ctag"] != "NUM":
            ud_graph.get_by_address(address).update({"ctag": "NUM"})


def fix_mark_tag(ud_graph: "UniversalDependencyGraph"):
    """
    A word tagged as PART must have the deprel 'mark'
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["ctag"] == "PART" and node["rel"] != "mark":
            ud_graph.get_by_address(address).update({"rel": "mark"})


def fix_cconj_rel(ud_graph: "UniversalDependencyGraph"):
    """
    The coordinating conjunction 'og' should have the deprel 'cc'
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["word"] == "og" and node["ctag"] == "CCONJ" and node["rel"] == "amod":
            ud_graph.get_by_address(address).update({"rel": "cc"})


def fix_cc_tag(ud_graph: "UniversalDependencyGraph"):
    """
    A word with the deprel 'cc' cannot be tagged 'PRON' and a word cannot be dependent on it
    ie. annaðhvort
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if node["rel"] == "cc" and node["ctag"] == "PRON":
            ud_graph.get_by_address(address).update({"ctag": "CCONJ"})
            if ud_graph.get_by_address(address + 1)["head"] == address:
                ud_graph.get_by_address(address + 1).update({"head": node["head"]})


def fix_cc_rel(ud_graph: "UniversalDependencyGraph"):
    """
    A node with the deprel 'cc' between two other nodes should be dependent on the latter node.
    """

    items = list(ud_graph.nodes.items())
    for address, node in items:
        if (
            node["rel"] == "cc"
            and node["head"] == address - 1
            and ud_graph.get_by_address(address + 1)["head"] == address - 1
        ):
            ud_graph.get_by_address(address).update({"head": address + 1})
            # The latter node should have the deprel 'conj'
            if ud_graph.get_by_address(address + 1)["rel"] != "conj":
                ud_graph.get_by_address(address + 1).update({"rel": "conj"})
            # If the former node is tagged 'ADJ', it should have the deprel 'amod'
            if (
                ud_graph.get_by_address(address - 1)["rel"] == "conj"
                and ud_graph.get_by_address(address - 1)["ctag"] == "ADJ"
            ):
                ud_graph.get_by_address(address - 1).update({"rel": "amod"})

        # The latter node should be dependent on the former node if the former node has the deprel 'amod'
        elif (
            node["rel"] == "cc"
            and node["head"] == address + 1
            and ud_graph.get_by_address(address + 1)["head"] > address + 1
            and ud_graph.get_by_address(address - 1)["rel"] == "amod"
        ):
            ud_graph.get_by_address(address + 1).update({"head": address - 1})
        # elif (
        #    node["rel"] == "cc"
        #    and node["head"] == ud_graph.get_by_address(address + 1)["head"]
        #    and ud_graph.get_by_address(address + 1)["ctag"] == "NOUN"
        #    and ud_graph.get_by_address(address + 1)["rel"] == "conj"
        # ):
        #    ud_graph.get_by_address(address).update({"head": address + 1})


def fix_cc_head(ud_graph: "UniversalDependencyGraph"):
    items = list(ud_graph.nodes.items())
    for address, node in items:
        if (
            node["rel"] == "cc"
            and ud_graph.get_by_address(address - 1)["head"] == address
            and ud_graph.get_by_address(address - 1)["rel"] == "advmod"
        ):
            ud_graph.get_by_address(address).update({"rel": "mark"})
        elif (
            node["rel"] == "cc"
            and ud_graph.get_by_address(address + 1)["head"] == address
            and ud_graph.get_by_address(address + 1)["rel"] == "cc"
        ):
            ud_graph.get_by_address(address + 1).update({"rel": "fixed"})
        elif (
            node["rel"] == "cc"
            and ud_graph.get_by_address(address - 1)["head"] == address
            and ud_graph.get_by_address(address - 2)["head"] == address
        ):
            ud_graph.get_by_address(address - 2).update(
                {"head": node["head"], "rel": node["rel"]}
            )
            ud_graph.get_by_address(address - 1).update(
                {"head": address - 2, "rel": "fixed"}
            )
            ud_graph.get_by_address(address).update(
                {"head": address - 2, "rel": "fixed"}
            )


def fix_conj_rel(ud_graph: "UniversalDependencyGraph"):
    """
    Various fixes to nodes with the deprel 'conj'
    """

    try:
        items = list(ud_graph.nodes.items())
        for address, node in items:
            # A node with the deprel 'conj' should never be dependent on itself
            if node["rel"] == "conj" and node["head"] == address:
                ud_graph.get_by_address(address).update(
                    {"head": ud_graph.get_by_address(address - 1)["head"]}
                )

            # If a node with the deprel 'conj' is dependent on the following word
            if node["rel"] == "conj" and node["head"] == address + 1:
                if (
                    ud_graph.get_by_address(address + 1)["rel"] == "obl"
                ):  # TODO: bæta við 'obl:arg'?
                    if node["ctag"] == "NOUN":
                        ud_graph.get_by_address(address).update({"rel": "nummod"})
                    elif node["ctag"] == "ADJ":
                        ud_graph.get_by_address(address).update({"rel": "amod"})
                    elif node["ctag"] == "PRON":
                        ud_graph.get_by_address(address).update({"rel": "det"})
                elif ud_graph.get_by_address(address + 1)["rel"] == "nsubj":
                    if node["ctag"] == "ADJ":
                        ud_graph.get_by_address(address).update({"rel": "amod"})
                elif ud_graph.get_by_address(address + 1)["rel"] in {
                    "amod",
                    "acl:relcl",
                }:
                    if node["ctag"] == "NOUN":
                        ud_graph.get_by_address(address).update({"rel": "nmod"})
                elif ud_graph.get_by_address(address + 1)["rel"] == "nmod:poss":
                    if node["ctag"] == "ADJ":
                        ud_graph.get_by_address(address).update({"rel": "amod"})
                elif ud_graph.get_by_address(address + 1)["rel"] == "advcl":
                    if node["ctag"] == "CCONJ":
                        ud_graph.get_by_address(address).update({"rel": "cc"})
                elif (
                    ud_graph.get_by_address(address - 6)["rel"] == "nsubj"
                    and ud_graph.get_by_address(address - 6)["head"] == node["head"]
                ):
                    ud_graph.get_by_address(address).update({"head": address - 6})
                elif ud_graph.get_by_address(address + 1)["rel"] == "ccomp":
                    if ud_graph.get_by_address(address)["lemma"] == "vera":
                        ud_graph.get_by_address(address).update({"rel": "cop"})
                elif ud_graph.get_by_address(address + 1)["rel"] == "obj":
                    if node["ctag"] == "PRON":
                        ud_graph.get_by_address(address).update({"rel": "det"})
                    elif node["ctag"] == "ADJ":
                        ud_graph.get_by_address(address).update({"rel": "amod"})

            # If a node with the deprel 'conj' is dependent on the node after the following node
            elif node["rel"] == "conj" and node["head"] == address + 2:
                if (
                    ud_graph.get_by_address(address + 2)["rel"] in {"root", "obl"}
                    and ud_graph.get_by_address(address + 2)["ctag"] == "NOUN"
                ):
                    if node["ctag"] == "ADV":
                        ud_graph.get_by_address(address).update({"rel": "advmod"})
                    elif node["ctag"] == "PROPN":
                        ud_graph.get_by_address(address).update({"rel": "nmod"})
                    elif node["ctag"] == "VERB":
                        ud_graph.get_by_address(address).update({"rel": "aux"})
                        ud_graph.get_by_address(address).update({"ctag": "AUX"})
                elif ud_graph.get_by_address(address + 2)["rel"] == "ccomp":
                    if node["ctag"] == "CCONJ":
                        ud_graph.get_by_address(address).update({"rel": "cc"})
                    elif (
                        ud_graph.get_by_address(address - 9)["rel"] == "nsubj"
                        and ud_graph.get_by_address(address - 9)["head"] == node["head"]
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 9})
                    elif (
                        ud_graph.get_by_address(address - 2)["rel"] == "cop"
                        and ud_graph.get_by_address(address - 2)["head"] == node["head"]
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 2})
                elif (
                    ud_graph.get_by_address(address + 2)["rel"] == "acl:relcl"
                    and ud_graph.get_by_address(address - 4)["rel"] == "nsubj"
                    and ud_graph.get_by_address(address - 4)["head"] == node["head"]
                ):
                    ud_graph.get_by_address(address).update({"head": address - 4})
                elif (
                    ud_graph.get_by_address(address + 2)["rel"] == "obj"
                    and ud_graph.get_by_address(address - 2)["rel"] == "amod"
                    and ud_graph.get_by_address(address - 2)["head"] == node["head"]
                    and ud_graph.get_by_address(address - 1)["rel"] == "cc"
                ):
                    if node["ctag"] == "ADJ":
                        ud_graph.get_by_address(address).update({"head": address - 2})

            elif node["rel"] == "conj" and node["head"] == address + 3:
                if ud_graph.get_by_address(address + 3)["rel"] == "obl":
                    if node["ctag"] == "VERB":
                        ud_graph.get_by_address(address).update({"rel": "amod"})
                    elif node["ctag"] == "ADJ":
                        ud_graph.get_by_address(address).update({"rel": "amod"})
                elif ud_graph.get_by_address(address + 3)["rel"] == "nsubj":
                    if node["ctag"] == "NOUN":
                        ud_graph.get_by_address(address).update({"rel": "nmod"})
                    elif node["ctag"] == "DET":
                        ud_graph.get_by_address(address).update({"rel": "amod"})
                elif ud_graph.get_by_address(address + 3)["rel"] == "advcl":
                    if node["ctag"] == "NOUN":
                        ud_graph.get_by_address(address).update({"rel": "nmod"})
                elif ud_graph.get_by_address(address + 3)["rel"] == "ccomp":
                    if ud_graph.get_by_address(address - 5)["rel"] == "nsubj":
                        ud_graph.get_by_address(address).update({"head": address - 5})
                    if (
                        node["ctag"] == "NOUN"
                        and ud_graph.get_by_address(address + 1)["rel"] == "cop"
                        and ud_graph.get_by_address(address + 1)["head"] == node["head"]
                    ):
                        ud_graph.get_by_address(address).update({"rel": "nsubj"})
                elif ud_graph.get_by_address(address + 3)["rel"] == "acl:relcl":
                    if (
                        ud_graph.get_by_address(address - 2)["rel"] == "advmod"
                        and ud_graph.get_by_address(address - 2)["head"] == node["head"]
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 2})
                elif (
                    ud_graph.get_by_address(address + 3)["rel"] == "nmod:poss"
                    and ud_graph.get_by_address(address - 4)["rel"] == "amod"
                    and ud_graph.get_by_address(address - 4)["head"] == node["head"]
                ):
                    ud_graph.get_by_address(address).update({"head": address - 4})
                elif ud_graph.get_by_address(address + 3)["rel"] in {"obj", "appos"}:
                    if node["ctag"] == "ADJ":
                        ud_graph.get_by_address(address).update({"rel": "amod"})

            elif node["rel"] == "conj" and node["head"] == address + 4:
                if ud_graph.get_by_address(address + 4)["rel"] == "obl":
                    if node["ctag"] == "ADV":
                        ud_graph.get_by_address(address).update({"rel": "advmod"})
                elif ud_graph.get_by_address(address + 4)["rel"] == "ccomp":
                    if (
                        ud_graph.get_by_address(address - 3)["rel"] == "nsubj"
                        and ud_graph.get_by_address(address - 3)["head"] == node["head"]
                    ):
                        ud_graph.get_by_address(address).update({"head": address - 3})
                elif ud_graph.get_by_address(address + 4)["rel"] == "conj":
                    ud_graph.get_by_address(address).update(
                        {"head": ud_graph.get_by_address(address + 4)["head"]}
                    )

            elif node["rel"] == "conj" and node["head"] == address + 5:
                if (
                    ud_graph.get_by_address(address + 5)["rel"] == "obl"
                    and ud_graph.get_by_address(address - 4)["rel"] == "nsubj"
                    and ud_graph.get_by_address(address - 4)["head"] == node["head"]
                ):
                    ud_graph.get_by_address(address).update({"head": address - 4})
                elif (
                    ud_graph.get_by_address(address + 5)["rel"] == "acl:relcl"
                    and ud_graph.get_by_address(address - 5)["rel"] == "nsubj"
                    and ud_graph.get_by_address(address - 5)["head"] == node["head"]
                ):
                    ud_graph.get_by_address(address).update({"head": address - 5})
                elif (
                    ud_graph.get_by_address(address + 5)["rel"] == "conj"
                    and ud_graph.get_by_address(address - 7)["rel"] == "nsubj"
                    and ud_graph.get_by_address(address - 7)["head"] == node["head"]
                ):
                    ud_graph.get_by_address(address).update({"head": address - 7})

            elif node["rel"] == "conj" and node["head"] == address + 6:
                if (
                    ud_graph.get_by_address(address + 6)["rel"] == "ccomp"
                    and ud_graph.get_by_address(address - 5)["rel"] == "nsubj"
                    and ud_graph.get_by_address(address - 5)["head"] == node["head"]
                ):
                    if node["ctag"] == "NOUN":
                        ud_graph.get_by_address(address).update({"head": address - 5})
                    elif node["ctag"] == "ADV":
                        ud_graph.get_by_address(address).update({"rel": "advmod"})
                elif (
                    ud_graph.get_by_address(address - 6)["rel"] == "nsubj"
                    and ud_graph.get_by_address(address - 6)["head"] == node["head"]
                ):
                    ud_graph.get_by_address(address).update({"head": address - 6})
                elif (
                    ud_graph.get_by_address(address + 6)["rel"] == "acl:relcl"
                    and ud_graph.get_by_address(address - 5)["rel"] == "nsubj"
                    and ud_graph.get_by_address(address - 5)["head"] == node["head"]
                ):
                    ud_graph.get_by_address(address).update({"head": address - 5})
                elif (
                    ud_graph.get_by_address(address + 6)["rel"] == "obl"
                    and node["ctag"] == "NOUN"
                ):
                    ud_graph.get_by_address(address).update({"rel": "obl"})

            elif node["rel"] == "conj" and node["head"] == address + 7:
                if (
                    ud_graph.get_by_address(address + 7)["rel"] == "ccomp"
                    and ud_graph.get_by_address(address - 3)["rel"] == "nsubj"
                    and ud_graph.get_by_address(address - 3)["head"] == node["head"]
                ):
                    ud_graph.get_by_address(address).update({"head": address - 3})
                elif (
                    ud_graph.get_by_address(address - 7)["rel"] == "obl"
                    and ud_graph.get_by_address(address - 7)["head"] == node["head"]
                ):
                    ud_graph.get_by_address(address).update({"head": address - 7})

            elif node["rel"] == "conj" and node["head"] == address + 13:
                if (
                    ud_graph.get_by_address(address + 13)["rel"] == "root"
                    and ud_graph.get_by_address(address - 7)["word"] == "þegar"
                    and ud_graph.get_by_address(address - 7)["head"] == address
                ):
                    ud_graph.get_by_address(address).update({"rel": "advcl"})
                elif node["ctag"] in {"NOUN", "VERB"}:
                    ud_graph.get_by_address(address).update({"rel": "dislocated"})

            elif node["rel"] == "conj" and node["head"] == address + 15:
                if (
                    ud_graph.get_by_address(address - 4)["rel"] == "dislocated"
                    and ud_graph.get_by_address(address - 4)["head"] == node["head"]
                ):
                    ud_graph.get_by_address(address).update({"head": address - 4})

    except RuntimeError:
        print(node)
        pass
        # raise
