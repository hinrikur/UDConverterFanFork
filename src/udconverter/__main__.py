import argparse
import os
import re
from sys import stdin, stdout

from nltk.data import path as nltk_path

from logic import depender
from utils.reader import IcePaHCFormatReader, IndexedCorpusTree
from utils.processing_scripts import (
    run_pre,
    run_post_file,
    fix_annotation_errors,
    load_corpus,
)


TREE = ""


def parse_arguments():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(description="Script for testing UD converter")

    parser.add_subparsers(
        dest="mode",
        help="mode for running the script",
        required=True,
    )

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

    return args


def process_no_corpus(args):
    """Process files when no corpus is specified."""
    # [Code for processing no_corpus goes here]


def process_single_tree(args, CORPUS):
    """Process a single tree based on ID number."""
    # [Code for processing single tree goes here]


def process_single_file(args, CORPUS):
    """Process a single file."""
    # [Code for processing single file goes here]


def process_corpus(args, CORPUS):
    """Process the entire corpus."""
    # [Code for processing entire corpus goes here]


def main():
    args = parse_arguments()
    nltk_path.extend([os.path.abspath(args.corpus_path)])
    CORPUS = None
    if args.CORPUS_NAME:
        CORPUS = load_corpus(args.CORPUS_NAME)

    if args.NO_CORPUS:
        process_no_corpus(args)
    elif args.ID_number:
        process_single_tree(args, CORPUS)
    elif args.file:
        process_single_file(args, CORPUS)
    elif args.corpus:
        process_corpus(args, CORPUS)
    else:
        print("Invalid input. Please specify the operation mode.")

    print("All done!")


if __name__ == "__main__":
    main()
