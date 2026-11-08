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


def test_confirmed_flow_wire_arg():
    files={
     "p.c":('BOOL reset(CTX* c, const FMT* fmt, UINT32 fpp){ size_t n = 100 / fmt->blk; return n; }'),
     "c.c":('void caller(wStream* s){ FMT fmt; Stream_Read_UINT16(s, fmt.blk); reset(ctx, &fmt, 0); }'),
    }
    from lykos.analyze.param_sink import confirmed_flows
    fl=confirmed_flows(files)
    assert any(ps.function=="reset" and ps.use=="divisor" for ps,_c,_f in fl)

def test_internal_object_not_flagged():
    files={
     "q.c":('void enq(Queue* q, void* item){ q->tail = (q->tail+1) %% q->len; }'),
     "u.c":('void use(void){ Queue* q = make(); enq(q, x); }'),  # q is internal, not wire
    }
    from lykos.analyze.param_sink import confirmed_flows
    assert not confirmed_flows(files)
