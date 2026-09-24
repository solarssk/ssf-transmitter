# ClusterFuzzLite requires this file at .clusterfuzzlite/Dockerfile.
# Extends the OSS-Fuzz base builder image for Python projects — same base
# image family the OSS-Fuzz-integrated projects (dnspython, pythainlp, ...)
# use, so `compile_python_fuzzer` and the sanitizer toolchain below are
# available without reinventing them.
#
# Pin by digest (repo convention — see Dockerfile's own header comment):
#   docker pull gcr.io/oss-fuzz-base/base-builder-python
#   docker inspect --format='{{index .RepoDigests 0}}' gcr.io/oss-fuzz-base/base-builder-python
# Dependabot's docker ecosystem entry for `/.clusterfuzzlite` proposes digest
# bumps automatically.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:182f0e4543c1285088fea0dd685febf7e623ba0c4035d24e574bc79bc239c33b

# `pip install .` isn't an option here: this image's own Python (3.11)
# predates pyproject.toml's requires-python (>=3.14), so pip refuses the
# install outright. Not a real loss — every fuzz/fuzz_*.py target only
# reaches into app.security, which is pure stdlib with no third-party
# dependencies — so making the package importable via PYTHONPATH covers
# it, and only copying app/ + fuzz/ (not the whole repo) keeps the fuzz
# image's surface to exactly what it fuzzes.
COPY app $SRC/ssf-transmitter/app
COPY fuzz $SRC/ssf-transmitter/fuzz
ARG PYTHONPATH=""
ENV PYTHONPATH="$SRC/ssf-transmitter:${PYTHONPATH}"
WORKDIR $SRC/ssf-transmitter

COPY .clusterfuzzlite/build.sh .clusterfuzzlite/requirements-atheris.txt $SRC/
