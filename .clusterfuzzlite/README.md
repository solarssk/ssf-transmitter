# ClusterFuzzLite build environment

This directory defines the isolated fuzzing image and its hash-pinned Atheris dependency. See [the fuzzing guide](../fuzz/README.md) for targets and local runs.

- `Dockerfile`: pinned OSS-Fuzz Python builder; copies `app/` and `fuzz/`.
- `build.sh`: installs the hashed dependency and compiles `fuzz_*.py` targets.
- `requirements-atheris.txt`: independent lock for the builder's Python version.

The builder's Python compatibility is separate from the Python 3.14 application. Do not replace this lock with application exports or install the whole project into the older builder interpreter.
