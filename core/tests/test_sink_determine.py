from lykos.analyze.sink_determine import determine

def test_switch_bounded_index_is_fp():
    body='switch(h.CapabilityType){ case CAP_GENERAL_TYPE: caps[h.CapabilityType]=1; break; }'
    v=determine(body,"h.CapabilityType","CWE-129","rdpdr_process_capability_request")
    assert v.verdict=="FP-bounded"

def test_range_checked_is_fp():
    body='Stream_Read_UINT32(s,NumFormats); if (NumFormats > 1000) return 0; x=NumFormats;'
    v=determine(body,"NumFormats","CWE-787","audin_process_formats")
    assert v.verdict=="FP-bounded"

def test_context_field_is_needs_state():
    body='ctx->indentLevels[ctx->currentLevel] += nbytes;'
    v=determine(body,"ctx->currentLevel","CWE-787","ndr_skip_bytes")
    assert v.verdict=="needs-state"

def test_outbound_is_outbound():
    v=determine("x","len","CWE-787","rdg_send_tunnel_request")
    assert v.verdict=="outbound"

def test_unguarded_wire_read_is_candidate():
    body='Stream_Read_UINT32(s, blen); Stream_Seek(s, blen);'
    v=determine(body,"blen","CWE-787","some_recv")
    assert v.verdict=="real-candidate"
