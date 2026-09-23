#!/usr/bin/python3
"""Fuzzing harness for app.security.log_sanitize.sanitize_for_log().

Checks the invariant the function documents, not just "doesn't crash":
its output is always a str, capped at max_len (+ the "...[truncated]"
suffix), with every C0 control character and DEL (\\x00-\\x1f, \\x7f)
stripped — the property CWE-117 log-line forgery depends on.
"""

import sys

import atheris

with atheris.instrument_imports():
    from app.security.log_sanitize import sanitize_for_log

_MAX_LEN = 200
_SUFFIX = "...[truncated]"


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())

    result = sanitize_for_log(text)

    if not isinstance(result, str):
        raise TypeError(f"sanitize_for_log returned {type(result)}, expected str")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in result):
        raise AssertionError("sanitize_for_log left a control character in its output")
    body = result[: -len(_SUFFIX)] if result.endswith(_SUFFIX) else result
    if len(body) > _MAX_LEN:
        raise AssertionError(f"sanitize_for_log output exceeds max_len={_MAX_LEN}: {len(body)}")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
