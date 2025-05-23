# -*- coding: utf-8 -*-

"""

Hinrik Hafsteinsson (hinhaf@hi.is)
Þórunn Arnardóttir (thar@hi.is)

Part of UniTree project for IcePaHC
"""

import os
import re
import argparse
import subprocess
import json
from sys import stdin, stdout

from nltk.corpus.util import LazyCorpusLoader
from nltk.data import path as nltk_path

from lib import depender
from lib.reader import IcePaHCFormatReader, IndexedCorpusTree

# from lib.tools import fix_IcePaHC_tree_errors, tagged_corpus


def run_pre(corpus_path):
    """Run preprocessing shell script for the given corpus."""
    subprocess.check_call(["./preProcess.sh", corpus_path])


def fix_annotation_errors(corpus_path, new_corpus_path):
    """Run error fix shell script for given .psd file"""
    subprocess.check_call(["./fix_corpus_errors.sh", corpus_path, new_corpus_path])


def run_post_file(file_path):
    """Run postprocessing shell script for given .conllu file"""
    subprocess.check_call(["./postProcessSingleFile.sh", file_path])


def load_corpus(name):
    corpus_loader = LazyCorpusLoader(
        f"{name}/psd",
        IcePaHCFormatReader,
        r".*\.psd",
        cat_pattern=r".*(nar|rel|sci|bio|law)\-.*",
    )
    return corpus_loader


TREE = ""


def main():
    """01.05.20

    Converts IcePaHC-format .psd corpus to Universal Dependencies framework

    """
    parser = argparse.ArgumentParser(description="Script for testing UD converter")
    parser.add_argument(
        "--pre_process",
        "-pr",
        action="store_true",
        help="flag for running PREprocessing script on corpus files",
    )
    parser.add_argument(
        "--post_process",
        "-po",
        action="store_true",
        help="flag for running POSTprocessing script on corpus files",
    )
    parser.add_argument(
        "--corpus_path",
        "-cpath",
        default="..",
        help="path to corpora parent folder, default is current working dir",
    )
    parser.add_argument(
        "--output", "-o", help="path to output folder", action="store_true"
    )
    parser.add_argument(
        "--auto_tag",
        "-tag",
        help="flag for automatically tagging input text",
        action="store_true",
    )

    input_type = parser.add_mutually_exclusive_group(required=True)
    input_type.add_argument(
        "--NO_CORPUS",
        "-N",
        help="no corpus, convert single file",
        action="store_true",
    )
    input_type.add_argument("--CORPUS_NAME", "-C", help="name of corpus folder")

    modes = parser.add_argument_group("input modes (1 required)")
    input_mode = modes.add_mutually_exclusive_group(required=True)
    input_mode.add_argument(
        "--ID_number", "-id", help="treebank ID number of tree to parse"
    )
    input_mode.add_argument(
        "--file", "-f", help="specific treebank file to parse as whole"
    )
    input_mode.add_argument(
        "--corpus",
        "-c",
        action="store_true",
        help="flag to parse whole Treebank corpus",
    )
    input_mode.add_argument(
        "--input",
        "-i",
        nargs="+",
        help="(IF NOT USING CORPUS PATH) path to single file to convert",
    )

    args = parser.parse_args()

    if args.file:
        file_id = args.file.lower()
        if file_id[-4] != ".psd":
            file_id += ".psd"

    if args.NO_CORPUS:
        c = depender.Converter()

        file_num = 0

        for path in args.input:
            psd = ""
            file_sents = 0
            file_num += 1

            input_path = path
            output_file = (
                re.sub(r"\.(gld|psd)", ".conllu", os.path.basename(input_path))
                if args.output
                else None
            )
            if "testset" in input_path:
                output_path = (
                    os.path.join("../CoNLLU/testset", output_file)
                    if output_file
                    else None
                )
            elif "devset" in input_path:
                output_path = (
                    os.path.join("../CoNLLU/devset", output_file)
                    if output_file
                    else None
                )
            else:
                output_path = (
                    os.path.join("../CoNLLU", output_file) if output_file else None
                )

            file_id = re.sub(r"\.gld", "", os.path.basename(input_path))

            with open(input_path) if input_path else stdin as infile, open(
                output_path, "w"
            ) if output_path else stdout as outfile:
                lines = infile.readlines()
                if not lines[-1].endswith("\n"):
                    lines.append("\n")
                for line in lines:
                    psd += line
                    if len(line.strip()) == 0 and len(psd.strip()) > 0:
                        dep = c.create_dependency_graph(psd)
                        sent_id = (
                            re.sub(r"\.gld", "", file_id).upper()
                            + ",."
                            + str(file_sents + 1)
                        )
                        sent_id = re.sub(r"/", "_", sent_id)
                        sent_id_line = "# sent_id = " + sent_id + "\n"

                        outfile.write(sent_id_line)
                        # outfile.write(str(dep.original_ID_plain_text()) + "\n")
                        outfile.write(str(c.add_space_after(dep).plain_text()) + "\n")
                        # outfile.write(str(dep.plain_text()) + "\n")
                        outfile.write(c.add_space_after(dep).to_conllU())

                        if not output_path:
                            input()
                        file_sents += 1
                        psd = ""

                if psd != "":
                    dep = c.create_dependency_graph(psd)
                    outfile.write(dep.to_conllU())

            if output_path and args.post_process:
                run_post_file(output_path)

            print(f"{file_num}\t{file_id}\t{file_sents+1}")

        exit()

    corpus_path = os.path.abspath(args.corpus_path)
    nltk_path.extend([corpus_path])
    CORPUS = load_corpus(args.CORPUS_NAME)

    if args.ID_number:
        if args.output:
            print("Single sentence cannot be written to file.")
            exit()
        INPUT_ID = args.ID_number
        file_id = INPUT_ID.split(",")[0].lower() + ".psd"
        tree_num = INPUT_ID.split(",")[1]

        for tree in CORPUS.parsed_sents(file_id):
            if tree.corpus_id_num == tree_num:
                TREE = tree.remove_nodes(tags=["CODE"], trace=True)
            else:
                continue

        try:
            # print(TREE)
            c = depender.Converter()
            dep = c.create_dependency_graph(TREE)
            dep = c.add_space_after(dep)
            print(dep.original_ID)
            print(dep.plain_text())
            print(dep.to_conllU())
            # input()
            psd = ""

        except ValueError:
            raise
            print(f"Error! No tree found for ID {INPUT_ID}\n")

    if args.file:
        # uses treebank PoS tags for UD features
        c = depender.Converter()

        to_join = []  # list for use in joining d.graphs into whole sentences
        file_sents = 0  # no. of sentence from current file

        # path to output saved if indicated, else saved as None
        output_file = (
            re.sub(r"(\.psd|\.gld)", ".conllu", file_id) if args.output else None
        )

        if "testset" in input_path:
            output_path = (
                os.path.join("../CoNLLU/testset", output_file) if output_file else None
            )
        elif "devset" in input_path:
            output_path = (
                os.path.join("../CoNLLU/devset", output_file) if output_file else None
            )
        else:
            output_path = (
                os.path.join("../CoNLLU", output_file) if output_file else None
            )

        with open(output_path, "w") if args.output else stdout as outfile:
            # open file if writing to output, else to stdout, either way called
            # 'outfile' in below code

            # counter set for missing tree IDs in corpus
            missing_id_counter = 0

            for tree in CORPUS.parsed_sents(file_id):
                # counter for missing IDs incremented for every tree in corpus
                missing_id_counter += 1
                # Tree static variable defined, code nodes and some traces removed
                TREE = tree.remove_nodes(tags=["CODE"], trace=True)

                # Tree ID created if missing
                if not TREE.corpus_id:
                    TREE.corpus_id = "ID_missing_" + str(missing_id_counter)

                dep = c.create_dependency_graph(TREE)

                # conversion happens below
                if (
                    dep.get_by_address(len(dep.nodes) - 1)["word"]
                    not in {".", ":", "?", "!", "kafli", '"'}
                    and len(dep.nodes) != 1
                ):
                    # checks for incomplete sentence (single clause) by checking
                    # puntuation and specific words (e.g. 'kafli')
                    to_join.append(dep)
                else:
                    # if end of sentence detected
                    try:
                        # try to print whole CoNLLU from dependency graph
                        # TODO: Fix redundancy of if/else statement
                        if len(to_join) == 0:
                            # there is nothing in 'to_join', so the sentence
                            # is complete already

                            # sentence ID saved as string using file_sent runner
                            sent_id = (
                                re.sub(r"\.psd", "", file_id).upper()
                                + ",."
                                + str(file_sents + 1)
                            )
                            sent_id = re.sub(r"\/", "_", sent_id)
                            sent_id_line = "# sent_id = " + sent_id + "\n"

                            # add NoSpaceAfter to misc column
                            dep = c.add_space_after(dep)

                            # output written:
                            # sentence ID
                            outfile.write(sent_id_line)
                            # sent ID from original treebank
                            outfile.write(str(dep.original_ID_plain_text()) + "\n")
                            # sentence text
                            outfile.write(
                                str(c.add_space_after(dep).plain_text()) + "\n"
                            )
                            # sentence CoNLLU
                            outfile.write(dep.to_conllU())

                            if not output_path:
                                # when writing to stdout, asks for user input (enter)
                                input()
                            file_sents += 1  # sentence count runner incremented by 1
                        else:
                            # dependency graphs in 'to_join' joined into single graph
                            # otherwise same as above
                            to_join.append(dep)
                            dep = c.add_space_after(c.join_graphs(to_join))

                            # sentence ID saved as string using file_sent runner
                            sent_id = (
                                re.sub(r"\.psd", "", file_id).upper()
                                + ",."
                                + str(file_sents + 1)
                            )
                            sent_id = re.sub(r"/", "_", sent_id)
                            sent_id_line = "# sent_id = " + sent_id + "\n"

                            # add NoSpaceAfter to misc column
                            dep = c.add_space_after(dep)

                            # output written:
                            # sentence ID
                            outfile.write(sent_id_line)
                            # sent ID from original treebank
                            outfile.write(str(dep.original_ID_plain_text()) + "\n")
                            # sentence text
                            outfile.write(
                                str(c.add_space_after(dep).plain_text()) + "\n"
                            )
                            # sentence CoNLLU
                            outfile.write(dep.to_conllU())

                            if not output_path:
                                # when writing to stdout, asks for user input (enter)
                                input()
                            file_sents += 1  # sentence count runner incremented by 1

                    except Exception as ex:
                        # catches any exception
                        raise
                        print("\n\n", dep.original_ID_plain_text(CORPUS="IcePaHC"))
                        print(f"{type(ex).__name__} for sentence: {ex.args}\n\n")
                    to_join = []

        if output_path and args.post_process:
            # if writing to file and postprocessing script indicated, runs
            # script on file
            run_post_file(output_path)

    if args.corpus:
        c = depender.Converter()

        fileids = CORPUS.fileids()

        for file_id in fileids:
            print(f"> Converting {file_id} ...", end="\r")

            to_join = []
            file_sents = 0  # no. of sentence from current file

            output_file = (
                re.sub(r"(\.psd|\.gld)", ".conllu", file_id) if args.output else None
            )

            if "testset" in input_path:
                output_path = (
                    os.path.join("../CoNLLU/testset", output_file)
                    if output_file
                    else None
                )
            elif "devset" in input_path:
                output_path = (
                    os.path.join("../CoNLLU/devset", output_file)
                    if output_file
                    else None
                )
            else:
                output_path = (
                    os.path.join("../CoNLLU", output_file) if output_file else None
                )

            with open(output_path, "w") if args.output else stdout as outfile:
                # counter set for missing tree IDs in corpus
                missing_id_counter = 0

                for tree in CORPUS.parsed_sents(file_id):
                    # counter for missing IDs incremented for every tree in corpus
                    missing_id_counter += 1

                    TREE = tree.remove_nodes(tags=["CODE"], trace=True)

                    # Tree ID created if missing
                    if not TREE.corpus_id:
                        TREE.corpus_id = "ID_missing_" + str(missing_id_counter)

                    dep = c.create_dependency_graph(TREE)

                    if (
                        dep.get_by_address(len(dep.nodes) - 1)["word"]
                        not in {".", ":", "?", "!", "kafli", '"'}
                        and len(dep.nodes) != 1
                    ):
                        to_join.append(dep)
                    else:
                        try:
                            if len(to_join) == 0:
                                # sentence ID saved as string using file_sent runner
                                sent_id = (
                                    re.sub(r"(\.psd\.gld)", "", file_id).upper()
                                    + ",."
                                    + str(file_sents + 1)
                                )
                                sent_id = re.sub(r"/", "_", sent_id)
                                sent_id_line = "# sent_id = " + sent_id + "\n"

                                # add NoSpaceAfter to misc column
                                dep = c.add_space_after(dep)

                                # output written:
                                # sentence ID
                                outfile.write(sent_id_line)
                                # sent ID from original treebank
                                outfile.write(str(dep.original_ID_plain_text()) + "\n")
                                # sentence text
                                outfile.write(
                                    str(c.add_space_after(dep).plain_text()) + "\n"
                                )
                                # sentence CoNLLU
                                outfile.write(dep.to_conllU())

                                if not output_path:
                                    input()

                                file_sents += (
                                    1  # sentence count runner incremented by 1
                                )

                            else:
                                to_join.append(dep)
                                dep = c.add_space_after(c.join_graphs(to_join))

                                # sentence ID saved as string using file_sent runner
                                sent_id = (
                                    re.sub(r"\.psd", "", file_id).upper()
                                    + ",."
                                    + str(file_sents + 1)
                                )
                                sent_id = re.sub(r"/", "_", sent_id)
                                sent_id_line = "# sent_id = " + sent_id + "\n"

                                # add NoSpaceAfter to misc column
                                dep = c.add_space_after(dep)

                                # output written:
                                # sentence ID
                                outfile.write(sent_id_line)
                                # sent ID from original treebank
                                outfile.write(str(dep.original_ID_plain_text()) + "\n")
                                # sentence text
                                outfile.write(
                                    str(c.add_space_after(dep).plain_text()) + "\n"
                                )
                                # sentence CoNLLU
                                outfile.write(dep.to_conllU())

                                if not output_path:
                                    input()

                                file_sents += (
                                    1  # sentence count runner incremented by 1
                                )

                        except Exception as ex:
                            raise
                            print("\n\n", dep.original_ID_plain_text(CORPUS="IcePaHC"))
                            print(f"{type(ex).__name__} for sentence: {ex.args}\n\n")
                        to_join = []
            print(f"> Converting {file_id} - Output sentences: {file_sents}")

    print("All done!")


if __name__ == "__main__":
    main()
