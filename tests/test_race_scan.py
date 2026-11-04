"""Double-fetch (CWE-367) and uninitialized-pointer (CWE-824) detectors — precision-first."""
from lykos.analyze.race_scan import find_double_fetch, find_uninit_ptr


def test_double_fetch_fires_on_check_then_refetch():
    src = """
    int handle(user_req_t* user) {
        if (user->len > MAX) return -1;      /* check reads user->len */
        char* dst = malloc(user->len);       /* re-fetch: value may have changed */
        memcpy(dst, user->data, user->len);  /* use reads user->len again */
        return 0;
    }
    """
    hits = find_double_fetch(src)
    assert any(h.field == "user->len" for h in hits)


def test_double_fetch_ignores_trusted_single_read():
    src = """
    int f(cfg_t* cfg) {
        if (cfg->size > 0) { total += cfg->size; }   /* cfg is config, trusted; and no use ctx */
        return 0;
    }
    int g(local_t* s) { int n = s->count; return n; }  /* single read, no check+use */
    """
    assert find_double_fetch(src) == []


def test_uninit_ptr_fires_on_deref_before_assign():
    src = """
    void f(void) {
        char* p;
        p->field = 1;     /* deref before any assignment -> uninitialized pointer */
    }
    """
    hits = find_uninit_ptr(src)
    assert any(h.ptr == "p" for h in hits)


def test_uninit_ptr_clears_on_assignment():
    src = """
    void g(void) {
        char* p;
        p = malloc(16);
        p[0] = 'x';       /* assigned first -> not uninitialized */
    }
    void h(void) {
        int* q;
        get(&q);          /* &q passed to initializer -> cleared */
        *q = 3;
    }
    """
    assert find_uninit_ptr(src) == []
