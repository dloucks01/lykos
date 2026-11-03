from lykos.analyze.intwidth import find_intwidth_bugs

def test_signed_read_used_as_size():
    src='void f(wStream* s){ INT32 len; Stream_Read_INT32(s, len); char* b = malloc(len); }'
    assert any(x.kind=="signed-size" for x in find_intwidth_bugs(src))

def test_truncation_wide_into_narrow():
    src='void f(wStream* s){ UINT16 n; Stream_Read_UINT32(s, n); memcpy(d, srp, n); }'
    assert any(x.kind=="truncation" for x in find_intwidth_bugs(src))

def test_unsigned_matched_width_clean():
    src='void f(wStream* s){ UINT32 n; Stream_Read_UINT32(s, n); char* b = malloc(n); }'
    assert not find_intwidth_bugs(src)

def test_no_size_use_clean():
    src='void f(wStream* s){ INT32 len; Stream_Read_INT32(s, len); other(len); }'
    assert not find_intwidth_bugs(src)
