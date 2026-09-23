# Fuzz testing

Coverage-guided fuzzing via [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/)
and [Atheris](https://github.com/google/atheris), the Python fuzzing engine
OSS-Fuzz itself uses.

## Layout

```text
.clusterfuzzlite/
├── Dockerfile   # OSS-Fuzz Python base builder image + this repo installed into it
└── build.sh     # installs atheris, compiles every fuzz/fuzz_*.py into a runnable fuzzer

fuzz/
├── fuzz_url_validation.py  # app.security.url_validation's SSRF-blocking logic
├── fuzz_log_sanitize.py    # app.security.log_sanitize.sanitize_for_log()
└── README.md
```

## Current targets

**`fuzz_url_validation.py`** exercises the deterministic pieces of
`validate_receiver_endpoint_url()` — scheme/credential/fragment rejection,
blocked-hostname/IP-literal checks (including the IPv4-in-IPv6 unwrapping for
mapped/6to4/Teredo/NAT64 addresses), and allowlist matching. It does not call
`validate_receiver_endpoint_url()` itself or the DNS resolution step: fuzz
targets need to stay fast and hermetic, and real network calls would make
this one slow, flaky, and dependent on external state.

**`fuzz_log_sanitize.py`** checks `sanitize_for_log()`'s documented
invariant — output is always a `str`, capped at `max_len`, with every C0
control character and DEL stripped (the property CWE-117 log-line forgery
defense depends on) — not just "doesn't crash".

## Running locally

Atheris needs Linux + a fuzzing-capable Clang; it has no prebuilt wheel for
macOS, and building one from source needs a custom Clang toolchain. Test
inside the same container CI uses instead of trying to install atheris on
the host:

```bash
docker build -f .clusterfuzzlite/Dockerfile -t ssf-transmitter-fuzz .
docker run --rm -it ssf-transmitter-fuzz bash -c '
  $SRC/build.sh
  $OUT/fuzz_url_validation -max_total_time=60
  $OUT/fuzz_log_sanitize -max_total_time=60
'
```

## CI integration

| Workflow | Trigger | Mode | Fuzz time |
| --- | --- | --- | --- |
| `fuzzing-pr.yml` | PRs touching `app/security/`, `fuzz/`, or `.clusterfuzzlite/` | `code-change` | 2 min, quits on first crash |
| `fuzzing-batch.yml` | Weekly (Sunday) | `batch` | 1 hour, reports every crash |

No storage repo is configured, so each run starts from scratch rather than a
corpus persisted across runs — still finds bugs, just without corpus
continuity. Wiring up a storage repo (a second, empty GitHub repo plus a
`PERSONAL_ACCESS_TOKEN` secret) is a reasonable follow-up if these targets
prove worth investing in further, not something to add speculatively now.

## Adding a target

1. Add `fuzz/fuzz_<name>.py` following the two existing targets' shape:
   `import atheris`, wrap the import of what you're fuzzing in
   `atheris.instrument_imports()`, define `TestOneInput(data: bytes)`, and a
   `main()` that calls `atheris.Setup(sys.argv, TestOneInput)` then
   `atheris.Fuzz()`.
2. `.clusterfuzzlite/build.sh` picks up any `fuzz_*.py` automatically — no
   workflow changes needed.
3. Prefer fuzzing pure, deterministic functions (parsing, validation,
   encoding) over anything doing I/O (network, filesystem, subprocess): I/O
   makes a fuzz target slow and non-deterministic, defeating coverage-guided
   fuzzing's whole point.
