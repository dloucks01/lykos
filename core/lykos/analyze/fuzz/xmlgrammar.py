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
# Regions where `<name>` is CHARACTER DATA, not a tag: a CDATA section, a comment, the DOCTYPE's
# internal subset (an entity value may hold markup). A "tag" matched in there and mutated -- text
# inserted after the `<raw>` inside `<![CDATA[<raw>]]>` -- edited data while the op believed it
# was editing structure, and nesting inserted there unbalanced nothing it meant to.
_OPAQUE = re.compile(rb"<!\[CDATA\[.*?\]\]>|<!--.*?-->|<!DOCTYPE[^\[>]*\[.*?\]\s*>", re.S)

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
_XXE_DECLS = (b'  <!ENTITY xxe SYSTEM "file:///etc/hostname">\n'
              b'  <!ENTITY lol "aaaaaaaaaa">\n'
              b'  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
              b'  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">\n')
_XXE_DOCTYPE = b'<!DOCTYPE root [\n' + _XXE_DECLS + b']>\n'
# An existing DOCTYPE up to where its internal subset opens (`[`) or the declaration closes (`>`):
# name, then an optional SYSTEM/PUBLIC external id.
_DOCTYPE_HEAD = re.compile(
    rb"<!DOCTYPE\s+[^\s\[>]+(?:\s+(?:SYSTEM|PUBLIC)(?:\s+(?:\"[^\"]*\"|'[^']*')){1,2})?\s*")

#: A mutant is never grown past this. Every operator ADDS (a 20,000-deep nest is 120 KB, an element
#: repeated 2,048 times is 2,048 copies of it) and a kept mutant is mutated again, so a lineage
#: compounded without limit: measured, 300 chained generations from a 70-byte seed reached
#: 4.98 MB, and every later op re-scanned the whole document. An op that would cross the cap is
#: skipped (truncating would break the well-formedness the mutator exists to keep).
_MAX_DOC = 1 << 19


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
        tags = list(_TAG.finditer(data))
        if tags and b"<!" in data:
            spans = [(m.start(), m.end()) for m in _OPAQUE.finditer(data)]
            if spans:
                tags = [t for t in tags
                        if not any(a <= t.start() < b for a, b in spans)]
        return tags

    @staticmethod
    def _insert_inside(data, t, body):
        """`body` as the first content of element `t`. A self-closing `<a/>` has no inside: text
        after it lands in its PARENT, and after a self-closing ROOT it lands outside the document
        -- which is not well-formed, so every op on `<cfg/>` used to produce a rejected input. A
        self-closing tag is opened up instead: `<a ...>body</a>`."""
        if t.group(3):
            return (data[:t.start(3)] + b">" + body + b"</" + t.group(1) + b">"
                    + data[t.end():])
        return data[:t.end()] + body + data[t.end():]

    @staticmethod
    def _element_end(data, t):
        """End offset of the element `t` opens: just past its matching `</name>`, counting nested
        same-name elements. None when the close tag is not found (a fragment)."""
        if t.group(3):
            return t.end()
        name = re.escape(t.group(1))
        rx = re.compile(rb"<(/?)" + name + rb"(?=[\s/>])[^>]*?(/?)>")
        depth = 1
        for m in rx.finditer(data, t.end()):
            if m.group(1):
                depth -= 1
                if depth == 0:
                    return m.end()
            elif not m.group(2):
                depth += 1
        return None

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
        return self._insert_inside(data, t, inner)

    def _entities(self, data):
        """Declare entities and reference them. Whether the parser expands or resolves these
        is the finding -- XXE and entity expansion both live here, and neither is reachable
        without a well-formed DOCTYPE."""
        out = data
        if b"<!DOCTYPE" not in out:
            m = re.match(rb"\s*<\?xml[^>]*\?>\s*", out)
            at = m.end() if m else 0
            out = out[:at] + _XXE_DOCTYPE + out[at:]
        elif b"<!ENTITY lol2 " not in out:
            # The document has its OWN DOCTYPE. Referencing &xxe; without declaring it is an
            # undefined-entity error, so the parser stopped at the reference and the entity code
            # under test never ran: declare ours inside the existing internal subset (or open
            # one), and only reference when that worked.
            m = _DOCTYPE_HEAD.search(out)
            if m is None:
                return None
            at = m.end()
            if out[at:at + 1] == b"[":
                out = out[:at + 1] + b"\n" + _XXE_DECLS + out[at + 1:]
            elif out[at:at + 1] == b">":
                out = out[:at] + b" [\n" + _XXE_DECLS + b"]" + out[at:]
            else:
                return None
        tags = self._tags(out)                           # element content only (see _OPAQUE)
        if tags:
            t = self.rng.choice(tags)
            ref = self.rng.choice((b"&xxe;", b"&lol2;", b"&lol1;"))
            out = self._insert_inside(out, t, ref)
        return out

    def _dup_element(self, data):
        """Repeat an element many times: list handling, and per-child allocation.

        The WHOLE element, start tag through its matching end tag. Repeating only the start tag
        (`<item id="x">` x 2048) left 2,048 unclosed elements -- measured with xmllint, 31 of 120
        such mutants were well-formed -- so the per-child code this op exists to stress was
        never reached. Copies go after the element as siblings; the root has no siblings, so its
        copies go inside it as children."""
        tags = self._tags(data)
        if not tags:
            return None
        t = self.rng.choice(tags)
        end = self._element_end(data, t)
        if end is None:
            return None
        frag = data[t.start():end]
        copies = frag * self.rng.choice((16, 256, 2048))
        if t.start() == tags[0].start():                 # the root element
            return self._insert_inside(data, t, copies)
        return data[:end] + copies + data[end:]

    def _text(self, data):
        """A very large text node, and the CDATA boundary."""
        tags = self._tags(data)
        if not tags:
            return None
        t = self.rng.choice(tags)
        body = self.rng.choice((b"A" * self.rng.choice(_LENGTHS),
                                b"<![CDATA[" + b"B" * 4096 + b"]]>",
                                b"&amp;" * 2048))
        return self._insert_inside(data, t, body)

    def mutate(self, data: bytes, corpus=()) -> bytes:
        if not looks_like_xml(data):
            return self.byte.mutate(data, corpus)
        ops = (self._grow_attr, self._many_attrs, self._deepen, self._entities,
               self._dup_element, self._text)
        out = data
        for _ in range(self.rng.randint(1, 2)):
            got = self.rng.choice(ops)(out)
            if got is not None and len(got) <= max(_MAX_DOC, len(out)):
                out = got
        # Occasionally break well-formedness on purpose: the error paths are code too, and a
        # mutator that only ever produces valid documents never tests them. Kept rare, because
        # that is the 99% a byte mutator already covers.
        if self.rng.random() < 0.05:
            out = self.byte.mutate(out, corpus)
        return out
