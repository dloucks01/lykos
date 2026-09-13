"""A mutator for XML, which is a grammar rather than a byte layout.

Byte mutation does not work on XML and the number is not close: measured against xmllint with
a valid seed, 2 of 200 mutants parsed cleanly. The other 198 were rejected at the syntax layer
-- a stray byte in a tag name ends the document before any semantic code runs -- so 99% of a
campaign tests the error path of the tokeniser.

The campaign does not LOOK starved while that happens, which is the trap. 3,000 executions
against xmllint produced 759 distinct "behaviours", because the behaviour proxy is the shape
of the program's output and a parser has a great many ways to say no. Distinct output is not
distinct code.

So generate XML that stays well-formed, and aim the mutation at the things that break real
parsers: attribute values that grow without bound, nesting that recurses, entity declarations
that expand, and element counts that stress whatever the parser allocates per child. The
structural attacks (deep nesting, entity expansion) are the ones a byte mutator can essentially
never reach, because they require the document to remain valid while it gets pathological.
"""
from __future__ import annotations

import re

from .mutator import Mutator

# Tag and attribute shapes in a seed we are mutating, not a general parser: we only need to
# find the pieces to vary, and anything we do not recognise is left alone.
_TAG = re.compile(rb"<([A-Za-z_][\w.:-]*)((?:\s+[\w.:-]+\s*=\s*\"[^\"]*\")*)\s*(/?)>")
_ATTR = re.compile(rb"([\w.:-]+)\s*=\s*\"([^\"]*)\"")

# Values chosen to break what is behind an attribute, not to look plausible. The long runs
# straddle the buffer sizes that appear in C parsers; the rest are the classic XML-specific
# hazards a length-only mutator never produces.
_LENGTHS = (63, 65, 255, 257, 1023, 4097, 65537)
_NASTY = (
    b"&xxe;", b"&lol9;", b"]]>", b"<![CDATA[", b"%remote;",
    b"../../../../etc/passwd", b"\xef\xbb\xbf", b"&#x41;" * 64,
    b"'\"><", b"\x00",
)
# A DOCTYPE that declares an external entity: the shape of XXE, and of the expansion attacks.
# Whether the parser resolves it is exactly what the campaign is asking.
_XXE_DOCTYPE = (b'<!DOCTYPE root [\n'
                b'  <!ENTITY xxe SYSTEM "file:///etc/hostname">\n'
                b'  <!ENTITY lol "aaaaaaaaaa">\n'
                b'  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
                b'  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">\n'
                b']>\n')


def looks_like_xml(data: bytes) -> bool:
    head = (data or b"")[:512].lstrip()
    return head.startswith(b"<?xml") or (head.startswith(b"<") and b">" in head)


class XmlMutator:
    """Grammar-aware XML mutator with the byte Mutator's interface.

    Falls back to byte havoc for input that is not XML, so a campaign that chose this model
    wrongly degrades to the old behaviour instead of mangling something it cannot parse.
    """

    def __init__(self, rng, dictionary=None):
        self.rng = rng
        self.byte = Mutator(rng, dictionary)

    # -- pieces -------------------------------------------------------------------------
    def _value(self) -> bytes:
        r = self.rng
        p = r.random()
        if p < 0.5:
            return r.choice((b"A", b"&#65;", b"../", b"\xc3\xa9")) * r.choice(_LENGTHS)
        if p < 0.85:
            return r.choice(_NASTY)
        return bytes(r.randrange(0x20, 0x7F) for _ in range(r.randint(1, 32)))

    def _tags(self, data):
        return [m for m in _TAG.finditer(data)]

    # -- mutations ----------------------------------------------------------------------
    def _grow_attr(self, data):
        """An attribute value that keeps growing -- the flat overflow case."""
        tags = self._tags(data)
        if not tags:
            return None
        t = self.rng.choice(tags)
        attrs = list(_ATTR.finditer(t.group(2) or b""))
        if not attrs:
            return None
        a = self.rng.choice(attrs)
        start = t.start(2) + a.start(2)
        end = t.start(2) + a.end(2)
        return data[:start] + self._value() + data[end:]

    def _many_attrs(self, data):
        """Hundreds of attributes on one element: whatever the parser allocates per attribute,
        at a scale the document's author never intended."""
        tags = self._tags(data)
        if not tags:
            return None
        t = self.rng.choice(tags)
        extra = b"".join(b' a%d="%s"' % (i, b"x" * self.rng.randint(1, 8))
                         for i in range(self.rng.choice((64, 256, 1024))))
        at = t.start(3) if t.group(3) else t.end(2)
        return data[:at] + extra + data[at:]

    def _deepen(self, data):
        """Nesting that recurses. A recursive-descent parser has a stack, and this is the
        input that finds its depth -- and it is unreachable by byte mutation, because every
        added level has to be balanced."""
        depth = self.rng.choice((64, 512, 4096, 20000))
        name = b"d"
        inner = b"<%s>" % name * depth + b"x" + b"</%s>" % name * depth
        tags = self._tags(data)
        if not tags:
            return data + inner
        t = self.rng.choice(tags)
        return data[:t.end()] + inner + data[t.end():]

    def _entities(self, data):
        """Declare entities and reference them. Whether the parser expands or resolves these
        is the finding -- XXE and entity expansion both live here, and neither is reachable
        without a well-formed DOCTYPE."""
        out = data
        if b"<!DOCTYPE" not in out:
            m = re.match(rb"\s*<\?xml[^>]*\?>\s*", out)
            at = m.end() if m else 0
            out = out[:at] + _XXE_DOCTYPE + out[at:]
        tags = self._tags(out)
        if tags:
            t = self.rng.choice(tags)
            ref = self.rng.choice((b"&xxe;", b"&lol2;", b"&lol1;"))
            out = out[:t.end()] + ref + out[t.end():]
        return out

    def _dup_element(self, data):
        """Repeat an element many times: list handling, and per-child allocation."""
        tags = self._tags(data)
        if not tags:
            return None
        t = self.rng.choice(tags)
        frag = data[t.start():t.end()]
        return data[:t.end()] + frag * self.rng.choice((16, 256, 2048)) + data[t.end():]

    def _text(self, data):
        """A very large text node, and the CDATA boundary."""
        tags = self._tags(data)
        if not tags:
            return None
        t = self.rng.choice(tags)
        body = self.rng.choice((b"A" * self.rng.choice(_LENGTHS),
                                b"<![CDATA[" + b"B" * 4096 + b"]]>",
                                b"&amp;" * 2048))
        return data[:t.end()] + body + data[t.end():]

    def mutate(self, data: bytes, corpus=()) -> bytes:
        if not looks_like_xml(data):
            return self.byte.mutate(data, corpus)
        ops = (self._grow_attr, self._many_attrs, self._deepen, self._entities,
               self._dup_element, self._text)
        out = data
        for _ in range(self.rng.randint(1, 2)):
            got = self.rng.choice(ops)(out)
            if got is not None:
                out = got
        # Occasionally break well-formedness on purpose: the error paths are code too, and a
        # mutator that only ever produces valid documents never tests them. Kept rare, because
        # that is the 99% a byte mutator already covers.
        if self.rng.random() < 0.05:
            out = self.byte.mutate(out, corpus)
        return out
