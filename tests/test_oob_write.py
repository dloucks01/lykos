"""Out-of-bounds write by index: a monotonic write-index never compared to a capacity, or an
attacker-controlled index with no bound. Precision first: any comparison of the index silences it."""
from lykos.analyze.fingerprint import oob_write as OW

SRC = r'''
typedef struct { Key keys[64]; unsigned nKeys; } State;

/* parser functions: their parameters carry attacker wire data (recv/parse/decode roles). */

void recv_keys(State* state, unsigned nslots)
{
	for (unsigned j = 0; j < nslots; j++) {
		Key* k = &state->keys[state->nKeys];   /* monotonic index, never bounded: OOB append */
		k->id = j;
		state->nKeys++;
	}
}

void recv_keys_safe(State* state, unsigned nslots)
{
	for (unsigned j = 0; j < nslots; j++) {
		if (state->nKeys >= 64)                 /* a real capacity check: quiet */
			break;
		Key* k = &state->keys[state->nKeys];
		state->nKeys++;
	}
}

void parse_write(char* buf, unsigned idx, char v)
{
	buf[idx] = v;                               /* attacker-controlled index, no bound: fires */
}

void parse_write_checked(char* buf, unsigned idx, unsigned n, char v)
{
	if (idx < n)                                /* bounded: quiet */
		buf[idx] = v;
}

void parse_fill(char* buf, unsigned n)
{
	for (unsigned i = 0; i < n; i++)            /* loop counter bounded by its own condition: quiet */
		buf[i] = 0;
}

void parse_const(char* buf)
{
	buf[7] = 0;                                 /* constant index: quiet */
}

/* a GENERIC (non-parser) helper: its parameter is an internal value a caller passed, NOT
   established attacker-controlled -- so the same unbounded index must NOT be flagged. */
void queue_put(State* state, unsigned nslots)
{
	for (unsigned j = 0; j < nslots; j++) {
		Key* k = &state->keys[state->nKeys];
		state->nKeys++;
	}
}

/* a capacity-ensuring helper bounds the write that follows it: quiet. */
void recv_bounded(State* state, unsigned nslots)
{
	ensure_capacity(state, nslots);
	state->keys[state->nKeys] = (Key){0};
	state->nKeys++;
}
'''


def _scan():
    return OW.scan_texts([("x.c", SRC)])


def test_monotonic_unbounded_index_fires():
    rows = [x for x in _scan() if x["kind"] == "monotonic-unbounded-index"]
    assert any("state->keys" in r["evidence"][0]["detail"] for r in rows)
    one = next(r for r in rows if "state->keys" in r["evidence"][0]["detail"])
    assert one["cwe"] == "CWE-787"


def test_capacity_check_silences_the_monotonic_case():
    details = " ".join(x["evidence"][0]["detail"] for x in _scan())
    # recv_keys_safe guards nKeys >= 64, so its keys[] write must not be flagged
    assert "recv_keys_safe" not in details


def test_attacker_index_fires_and_checked_index_is_quiet():
    rows = _scan()
    assert any("parse_write(" in x["evidence"][0]["detail"] for x in rows)
    details = " ".join(x["evidence"][0]["detail"] for x in rows)
    assert "parse_write_checked" not in details    # idx < n bound


def test_loop_counter_and_constant_index_are_quiet():
    details = " ".join(x["evidence"][0]["detail"] for x in _scan())
    assert "parse_fill" not in details             # i < n loop bound
    assert "parse_const" not in details            # constant index


def test_generic_function_index_is_not_flagged():
    """Precision: the same unbounded append in a GENERIC helper (queue_put) is NOT attacker-
    established -- its parameter is an internal object a caller passed, not wire data."""
    details = " ".join(x["evidence"][0]["detail"] for x in _scan())
    assert "queue_put" not in details


def test_capacity_ensuring_helper_silences_the_write():
    """A capacity-ensuring helper (ensure_capacity(state, ...)) bounds the following write: quiet."""
    details = " ".join(x["evidence"][0]["detail"] for x in _scan())
    assert "recv_bounded" not in details


def test_local_counter_table_walk_is_not_flagged():
    """The precision floor: a purely-LOCAL counter walking a static table / filling a scratch array
    (the dominant safe pattern) is NOT attacker-influenced and must stay quiet -- only a counter or
    index derived from a parameter / field / reader fires."""
    src = r'''
static const Entry TABLE[8] = { 0 };
int walk(void)
{
	Entry out[8];
	unsigned n = 0;
	for (unsigned i = 0; TABLE[i].name; i++)   /* local counter, static table: safe */
		out[n++] = TABLE[i];
	return n;
}
'''
    assert OW.scan_texts([("w.c", src)]) == []
