"""Out-of-bounds write by index: a monotonic write-index never compared to a capacity, or an
attacker-controlled index with no bound. Precision first: any comparison of the index silences it."""
from lykos.analyze.fingerprint import oob_write as OW

SRC = r'''
typedef struct { Key keys[64]; unsigned nKeys; } State;

void collect(State* state, unsigned nslots)
{
	for (unsigned j = 0; j < nslots; j++) {
		Key* k = &state->keys[state->nKeys];   /* monotonic index, never bounded: OOB append */
		k->id = j;
		state->nKeys++;
	}
}

void collect_safe(State* state, unsigned nslots)
{
	for (unsigned j = 0; j < nslots; j++) {
		if (state->nKeys >= 64)                 /* a real capacity check: quiet */
			break;
		Key* k = &state->keys[state->nKeys];
		state->nKeys++;
	}
}

void write_idx(char* buf, unsigned idx, char v)
{
	buf[idx] = v;                               /* attacker-controlled index, no bound: fires */
}

void write_idx_checked(char* buf, unsigned idx, unsigned n, char v)
{
	if (idx < n)                                /* bounded: quiet */
		buf[idx] = v;
}

void loop_fill(char* buf, unsigned n)
{
	for (unsigned i = 0; i < n; i++)            /* loop counter bounded by its own condition: quiet */
		buf[i] = 0;
}

void const_idx(char* buf)
{
	buf[7] = 0;                                 /* constant index: quiet */
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
    # collect_safe guards nKeys >= 64, so its keys[] write must not be flagged
    assert "collect_safe" not in details


def test_attacker_index_fires_and_checked_index_is_quiet():
    rows = _scan()
    assert any(x["kind"] == "attacker-index" and "write_idx(" not in x["title"] for x in rows) \
        or any("buf[idx]" in x["evidence"][0]["detail"] and "write_idx" in x["evidence"][0]["detail"]
               for x in rows)
    details = " ".join(x["evidence"][0]["detail"] for x in rows)
    assert "write_idx_checked" not in details      # idx < n bound


def test_loop_counter_and_constant_index_are_quiet():
    details = " ".join(x["evidence"][0]["detail"] for x in _scan())
    assert "loop_fill" not in details              # i < n loop bound
    assert "const_idx" not in details              # constant index


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
