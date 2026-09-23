#!/bin/bash -eu
# ClusterFuzzLite requires this file at .clusterfuzzlite/build.sh.
# Hash-pinned (--require-hashes) like the rest of this repo's installs; see
# requirements-atheris.txt. Pinned at all because atheris ships as a
# per-Python-version wheel, so an unpinned build isn't reproducible.
pip3 install --no-cache-dir --require-hashes -r "${SRC}/requirements-atheris.txt"

for fuzzer in "${SRC}/ssf-transmitter/fuzz"/fuzz_*.py; do
  compile_python_fuzzer "${fuzzer}"
done
