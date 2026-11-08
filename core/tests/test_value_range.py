from lykos.analyze.value_range import eval_expr, analyze_function, can_be_zero, max_value, Interval

def test_literal_interval():
    assert eval_expr("4", {}).lo == 4 and eval_expr("4", {}).hi == 4

def test_wire_read_full_range_can_be_zero():
    body='UINT16 nb; Stream_Read_UINT16(s, nb);'
    assert can_be_zero("nb", body)                 # unguarded wire value includes 0

def test_guarded_nonzero_cannot_be_zero():
    body='UINT16 nb; Stream_Read_UINT16(s, nb); if (nb == 0) return 1;'
    assert not can_be_zero("nb", body)             # guard excludes 0

def test_dsp_shape_divisor_includes_zero():
    # data_per_block = (nBlockAlign - 4*nChannels)*8 ; nBlockAlign,nChannels wire, unguarded
    body=('UINT16 nBlockAlign; UINT16 nChannels; Stream_Read_UINT16(s,nBlockAlign);'
          ' Stream_Read_UINT16(s,nChannels); dpb = (nBlockAlign - 4*nChannels)*8;')
    assert can_be_zero("dpb", body)

def test_arith_propagation():
    body='UINT8 a; Stream_Read_UINT8(s,a); b = a + 1;'
    assert max_value("b", body) == 256            # 0..255 + 1

def test_literal_divisor_not_zero():
    assert not can_be_zero("8", "x = 1;")
