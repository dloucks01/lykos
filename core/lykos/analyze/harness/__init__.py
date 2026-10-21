"""Harness synthesis (doc 46): turn a recovered binary into fuzzable units.

T1 -- `rank`: score functions by fuzz-worthiness so the fuzzer drives the parsers that matter,
not `main()`. T2 (later) -- synthesize an emulated single-function harness for the top targets.
"""
