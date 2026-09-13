"""XML is a grammar, not a byte layout.

Byte mutation does not work on it, and the number is not close: measured against xmllint with
a valid seed, 2 of 200 mutants parsed cleanly. The other 198 died in the tokeniser, so 99% of
a campaign tested the error path.

The campaign does not look starved while that happens, which is the trap -- 3,000 executions
produced 759 distinct "behaviours", because the behaviour proxy is output shape and a parser
has a great many ways to say no. Distinct output is not distinct code.
"""
import random

from lykos.analyze.fuzz import structure
from lykos.analyze.fuzz.xmlgrammar import XmlMutator, looks_like_xml

SEED = b'<?xml version="1.0"?>\n<root a="1"><item id="x">text</item><item/></root>\n'


def test_xml_is_recognised_and_other_input_is_not():
    assert looks_like_xml(SEED)
    assert looks_like_xml(b"  <config><a/></config>")
    assert not looks_like_xml(b"\x47\x00\x21\x20" + b"\x00" * 100)
    assert not looks_like_xml(b"name=prod\nworkers=4\n")
    assert not looks_like_xml(b"")


def test_mutants_stay_well_formed_often_enough_to_reach_the_parser():
    """Not "always": breaking well-formedness on purpose is a real test too, and the mutator
    does it deliberately about 5% of the time. What matters is that the majority now reach
    semantic code, where byte mutation put 1% there."""
    m = XmlMutator(random.Random(5))
    balanced = 0
    for _ in range(200):
        out = m.mutate(SEED)
        # a cheap proxy for the real measurement (xmllint parsing it): the document still
        # opens and closes its root
        if out.count(b"<root") >= 1 and out.count(b"</root>") >= 1:
            balanced += 1
    assert balanced > 140, f"only {balanced}/200 kept the document structure"


def test_the_structural_attacks_byte_mutation_cannot_reach():
    """Deep nesting and entity expansion require the document to stay VALID while it becomes
    pathological, which is why a byte mutator essentially never produces them."""
    m = XmlMutator(random.Random(3))
    seen = {"deep": False, "entity": False, "attrs": False}
    for _ in range(400):
        out = m.mutate(SEED)
        if out.count(b"<d>") > 50:
            seen["deep"] = True
        if b"<!ENTITY" in out:
            seen["entity"] = True
        if out.count(b'a0="') and out.count(b'a63="'):
            seen["attrs"] = True
    assert all(seen.values()), seen


def test_non_xml_falls_back_to_byte_havoc():
    """A campaign that picked this model wrongly must degrade to the old behaviour rather than
    mangle something it cannot parse."""
    m = XmlMutator(random.Random(1))
    out = m.mutate(b"\x89PNG\r\n\x1a\n" + bytes(64))
    assert isinstance(out, bytes) and out


def test_a_three_letter_token_is_not_evidence_of_a_format():
    """"PAT" is a real MPEG-TS term and useless as evidence: it matched "MAX_PATHS reached"
    and detected xmllint as a transport-stream parser -- worse than detecting nothing, because
    the campaign would then generate TS packets for an XML parser."""
    assert not structure._token_hit("PAT", "MAX_PATHS reached: too many paths")
    # ...but a short token that appears as a WORD still counts
    assert structure._token_hit("PNG", "PNG image data, 8-bit")
    assert structure._token_hit("IHDR", "IHDR chunk")
    # and no builtin still carries a token that cannot be evidence
    for name, entry in structure._BUILTINS.items():
        for tok in entry["tokens"]:
            assert tok not in ("PAT", "PMT"), f"{name} still claims {tok!r}"


def test_detection_still_works_on_the_corpus_formats():
    assert structure.detect_format(["GIF89a", "DGifOpenFileName"]) == "gif"
    assert structure.detect_format(["Exif", "JFIF", "jpeg"]) == "jpeg"
    assert structure.detect_format(["PNG", "IHDR", "IDAT"]) == "png"
    assert structure.detect_format(["MAX_PATHS reached", "xmlParseDoc"]) is None
