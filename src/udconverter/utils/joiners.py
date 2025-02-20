import re
import os
from datetime import datetime
from collections import defaultdict
import pyconll

"""

# TODO:
    FINISH IMPLEMENTING join_various_nodes() method

Hinrik Hafsteinsson
Þórunn Arnardóttir
Part of UniTree project for IcePaHC

Module for joining various nodes in IcePaHC files split by '$'
"""


class SentJoiner:
    """ """

    def __init__(self, graph_list):
        # self.input_lines = file.readlines()
        # self.path = file.name
        # self.line_indexes = range(len(self.input_lines))
        # self.last_num = None
        # self.name = os.path.basename(file.name)
        # self.joined_sents = []
        self.sent_num = len(graph_list)
        self.new_token_ID = 0
        self.old_new_tokens = defaultdict(None)
        self.token_key = None
        self.first_root = None
        # self.lines = []

    def _join_sents(self):
        joined = ""
        for i in self.line_indexes:
            # self.input_lines[i] = self.input_lines[i].split('\t')
            if self.input_lines[i][0] in {"#", "\n"}:
                continue
            # elif self.input_lines[i+1]: # for catching eof
            if re.search(r"^1\t[A-ZÞÆÐÖÁÉÝÚÍÓ]", self.input_lines[i]):
                # self.joined_sents.append(new_sent)
                # new_sent = ''
                joined += "\n"
                joined += self.input_lines[i]
            else:
                joined += self.input_lines[i]
        # self.joined_sents = [pyconll.load_from_string(sentence) for sentence in corpus.joined_sents]
        self.joined_sents = joined

    def _set_sent_ID(self):
        ID = "%s_%s" % (self.name, self.sent_num)
        return ID

    def _get_keys(self):
        self.token_key = token.form + "-" + token.id

    def _set_token_IDs(self, sentence):
        subsentence = 0
        for token in sentence:
            if "-" in token.id:
                return sentence
            if token.id == "1":
                subsentence += 1
            self.new_token_ID += 1
            placeholder_ID = ".".join(
                [token.id, str(self.new_token_ID), str(subsentence)]
            )
            # print(token.id, token.form)
            self.token_key = "-".join([token.form, placeholder_ID, str(subsentence)])
            # self.new_token_ID += 1
            if int(token.id) != self.new_token_ID:
                self.old_new_tokens[token.id] = token.form, str(self.new_token_ID)
                token.id = placeholder_ID
                # print('Old:', token.id, token.form)
                # print('New:', token.id, token.form)
                # print('\t', token.id)
        for token in sentence:
            if not "." in token.id:
                # print(token.conll())
                if token.deprel == "root":
                    self.first_root = token.id
            else:
                try:
                    token.head = self.old_new_tokens[token.head][1]
                    # print(token.conll())
                except KeyError:
                    token.head = self.first_root
                    token.deprel = "conj"
                    # print(token.conll())
                finally:
                    token.id = token.id.split(".")[1]

        return sentence

    def _add_to_fixed(self, sent):
        self.lines.append(sent)
        self.lines.append("\n\n")

    def set_vars(self):
        """
        Sets all object attributes for CoNLL-U file
        """
        # sentences joined based on punctuation
        self._join_sents()
        # CoNLL-U object read from string as iterable
        conll = pyconll.iter_from_string(self.joined_sents)  # reads sentence
        # iterated through sentences
        for sentence in conll:
            self.sent_num += 1
            # function called to set sentence ID
            sentence.id = self._set_sent_ID()
            # function called to set token IDs and fix dependency heads
            sentence = self._set_token_IDs(sentence)
            # new token ID attribute zeroed out
            self.new_token_ID = 0
            # print(sentence.conll())
            # print(self.old_new_tokens)

            # input()
            self.old_new_tokens = defaultdict(None)
            self._add_to_fixed(str(sentence.conll()))


class FileWriter:
    """
    Class to write .lines attribute of a Joiner object (NodeJoiner,
    SentJoiner) to an output file.
    """

    def __init__(self, file):
        self.file = file
        f = open(file, "r")
        self.lines = f.readlines()
        self.path = file
        self.name = os.path.basename(file)
        # self.j = Joiner
        self.out_dir = (
            os.path.dirname(self.path) + "_out" + datetime.today().strftime("_%d-%m-%Y")
        )

    def _create_out_dir(self):
        if not os.path.isdir(self.out_dir):
            os.mkdir(self.out_dir)

    def write_to_file(self, **kwargs):
        """
        Writes "corrected" lines of input to output file
        Required args: sepdir
            If sepdir=True: Output file goes to seperate directory
            If sepdir=False: Output file goes to input directory
        Optional args: overwrite
            If overwrite=True: Output file overwrites input file
        """
        # print(self.path)
        print("name:", self.name)

        sepdir = kwargs.get("sepdir", None)
        overwrite = kwargs.get("overwrite", None)
        if sepdir == True and overwrite == True:
            print("Overwrite not possible if separate output directory")
            return
        if sepdir == True:
            self._create_out_dir()
            outname = os.path.join(self.out_dir, self.name + ".tmp")
        else:
            outname = self.path + ".tmp"
        if os.path.exists(outname):
            print("File already exists. Run script again.")
            os.remove(outname)
            return
        with open(outname, "w") as file:
            print("Writing to file:", self.name)
            for line in self.lines:
                print(line)
                file.write(line)
        if overwrite == True:
            os.remove(self.path)
            os.rename(outname, self.path)


if __name__ == "__main__":
    for file in os.listdir("../../corpora/GreynirCorpus/testset/psd"):
        # for file in os.listdir('testing/CoNLLU_output'):
        # IN_FILE = os.path.join('testing/CoNLLU_output', file)
        #    IN_FILE = os.path.join("../../testing/corpora/GreynirCorpus/testset/psd", file)
        # IN_FILE = sys.argv[1]
        #    file = open(IN_FILE, "r")
        # j = NodeJoiner(file)
        #    j = FileWriter(file)
        #    print(j.name)
        print(
            os.path.join(
                "/Users/torunnarnardottir/Vinna/UDConverter-GreynirCorpus/corpora/GreynirCorpus/testset/psd",
                file,
            )
        )
        # print(os.path.abspath(file))
        f1 = FileWriter(
            os.path.join(
                "/Users/torunnarnardottir/Vinna/UDConverter-GreynirCorpus/corpora/GreynirCorpus/testset/psd",
                file,
            )
        )
        f1.write_to_file(sepdir=False, overwrite=True)

        # j.iterate_nodes()
        # for current_line_num in j.indexes:
        #     # print(current_line_num)
        #     # if j.file_type == '.psd':
        #     j.join_various_nouns(current_line_num)
        # elif j.file_type == '.conllu':
        #     pass
        # j.write_to_file(sepdir=True, overwrite=False)
        # for name in os.listdir(IN_DIR):
        #     file = open(os.path.join(IN_DIR, name), 'r')
        #     j = NodeJoiner(file)
        #     j.iterate_nodes()
        #     j.write_to_file(sepdir=False, overwrite=True)
        # print('Done.')
