import subprocess

from ..utils.reader import IcePaHCFormatReader, IndexedCorpusTree
from nltk.corpus.reader import LazyCorpusLoader


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
