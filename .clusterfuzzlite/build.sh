#!/bin/bash -eu
# ClusterFuzzLite requires this file at .clusterfuzzlite/build.sh.
# Pinned exactly (not the loose atheris floor any other extra would use):
# atheris ships as a source-built wheel per Python version, and pinning it
# keeps a fuzzer build reproducible the same way this repo pins pip-tools
# for the same reason (see ci.yml's "Install pip-tools" step).
pip3 install --no-cache-dir "atheris==2.3.0"

for fuzzer in "${SRC}/ssf-transmitter/fuzz"/fuzz_*.py; do
  compile_python_fuzzer "${fuzzer}"
done
