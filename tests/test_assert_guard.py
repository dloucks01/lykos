"""Assert-only bounds checks: a copy whose only length guard is an assertion is unchecked in builds
that compile the assertion out, and an abort where it is kept. The detector discovers the tree's
own assert-like macros, finds copy helpers guarded only by them, and flags callers that pass a
length they never checked with a real branch. Precision first: a real `if` guard silences it."""
from lykos.analyze.fingerprint import assert_guard as AG

HDR = r'''
#define PROJ_ASSERT_AT(c, f, l) do { if (!(c)) proj_abort(#c, f, l); } while (0)
#define PROJ_ASSERT(cond) PROJ_ASSERT_AT((cond), __FILE__, __LINE__)
typedef struct { unsigned char* cur; size_t cap; size_t used; } buf;
static inline size_t buf_remaining(const buf* b) { return b->cap - b->used; }
static inline void buf_write(buf* b, const void* p, size_t n)
{
	PROJ_ASSERT(buf_remaining(b) >= n);
	memcpy(b->cur, p, n);
	b->cur += n;
}
static inline void buf_write_checked(buf* b, const void* p, size_t n)
{
	if (buf_remaining(b) < n)
		return;
	memcpy(b->cur, p, n);
}
'''

SRC = r'''
#include "buf.h"
struct ctx { unsigned char* token; size_t tokenLength; };

int send_request(struct ctx* c)
{
	buf* s = buf_new(NULL, 512);
	buf_write(s, c->token, c->tokenLength);          /* unchecked: fires */
	return 0;
}

int send_checked(struct ctx* c)
{
	buf* s = buf_new(NULL, 512);
	if (c->tokenLength > 256)
		return -1;
	buf_write(s, c->token, c->tokenLength);          /* real guard: quiet */
	return 0;
}

int send_constant(buf* s)
{
	buf_write(s, "abcd", 4);                         /* constant length: quiet */
	buf_write_checked(s, "abcd", 4);
	return 0;
}

int parse_hdr(buf* s)
{
	unsigned int count = 0;
	buf_read_u32(s, count);
	PROJ_ASSERT(count < 16);                          /* reachable assertion on input */
	return (int)count;
}
'''


def _scan():
    return AG.scan_texts([("buf.h", HDR), ("proto.c", SRC)])


def test_discovers_project_assert_macros():
    names = AG.discover_assert_macros([AG.strip_code(HDR)])
    assert {"assert", "PROJ_ASSERT", "PROJ_ASSERT_AT"} <= names


def test_unchecked_caller_of_assert_guarded_helper_fires_with_fixed_capacity():
    f = [x for x in _scan() if x["cwe"] == "CWE-787"]
    hits = {(x["file"], "send_request" in x["title"]) for x in f}
    assert ("proto.c", True) in hits
    one = next(x for x in f if "send_request" in x["title"])
    assert one["fixed"] == 512 and one["severity"] == "high"
    assert "buf.h" in one["evidence"][0]["detail"]          # names where the assert-only guard is


def test_real_guard_and_constant_lengths_stay_quiet():
    titles = " ".join(x["title"] for x in _scan())
    assert "send_checked" not in titles
    assert "send_constant" not in titles
    assert "buf_write_checked" not in titles                # a real check makes it not a wrapper


def test_reachable_assertion_on_input_value():
    r = [x for x in _scan() if x["cwe"] == "CWE-617"]
    assert len(r) == 1 and "count" in r[0]["title"] and "parse_hdr" in r[0]["title"]


def test_static_assert_is_not_a_runtime_guard():
    names = AG.discover_assert_macros(["#define CHECK_LAYOUT(x) static_assert(x, \"layout\")"])
    assert "static_assert" not in names


def test_strip_code_keeps_lines_and_hides_braces_in_strings():
    s = 'a = "{ not a brace }"; /* { */\nb = 1; // }\n'
    out = AG.strip_code(s)
    assert out.count("\n") == s.count("\n") and "{" not in out and "}" not in out
