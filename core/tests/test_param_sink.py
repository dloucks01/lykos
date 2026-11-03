from lykos.analyze.param_sink import find_param_sinks

def test_param_field_divisor_derived_local():
    # the DSP shape: divisor is a local computed from param->fields, unvalidated
    src=('BOOL reset(CTX* c, const AUDIO_FORMAT* fmt, UINT32 fpp){'
         ' size_t dpb=(fmt->nBlockAlign - 4*fmt->nChannels)*8;'
         ' size_t nb = min_frame / dpb; return nb; }')
    ps=find_param_sinks(src)
    assert any(x.use=="divisor" for x in ps)

def test_validated_param_suppressed():
    src=('int f(int* arr, int i){ if (i >= 10) return 1; arr[i]=0; return 0; }')
    assert not any(x.use=="index" for x in find_param_sinks(src))

def test_unvalidated_param_index():
    src=('int f(int* arr, int i){ arr[i]=0; return 0; }')
    assert any(x.use=="index" for x in find_param_sinks(src))
