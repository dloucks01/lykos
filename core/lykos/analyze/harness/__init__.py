"""Harness synthesis (doc 46): turn a recovered binary into fuzzable units.

T1 -- `rank`: score functions by fuzz-worthiness so the fuzzer drives the parsers that matter,
not `main()`. T2 -- `emulate`/`fuzz`: drive a top-ranked function directly under unicorn (binary
libFuzzer) and the `harness` stage that files the function-level faults it finds.
"""
from .harness_stage import HARNESS_STAGE, enqueue_harness, harness_stage  # noqa: F401
from .harness_stage import register as register  # noqa: F401,PLC0414

