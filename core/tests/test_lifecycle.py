from lykos.analyze.lifecycle import find_lifecycle_bugs

def test_use_after_free():
    src='void f(void){\n T* p=make();\n free(p);\n p->x = 1;\n}'
    assert any(x.kind=="use-after-free" for x in find_lifecycle_bugs(src))

def test_double_free():
    src='void f(void){\n T* p=make();\n free(p);\n free(p);\n}'
    assert any(x.kind=="double-free" for x in find_lifecycle_bugs(src))

def test_reassign_clears():
    src='void f(void){\n T* p=make();\n free(p);\n p=make();\n p->x=1;\n}'
    assert not find_lifecycle_bugs(src)

def test_null_after_free_safe():
    src='void f(void){\n T* p=make();\n free(p);\n p=NULL;\n free(p);\n}'
    assert not any(x.kind=="double-free" for x in find_lifecycle_bugs(src))

def test_clean_no_bug():
    src='void f(void){\n T* p=make();\n p->x=1;\n free(p);\n}'
    assert not find_lifecycle_bugs(src)


# --- precision regressions (the FreeRDP 740->67 FP cull) ---

def test_switch_case_exclusive_frees_not_double_free():
    """free(p) in two sibling switch cases (each break;) are mutually exclusive, not a double-free."""
    src = """
    void f(msg_t* msg, int t) {
        switch (t) {
            case 1: free(msg->wParam); break;
            case 2: free(msg->wParam); break;
            case 3: free(msg->wParam); break;
        }
    }
    """
    assert not any(b.kind == "double-free" for b in find_lifecycle_bugs(src))


def test_early_return_severs_use():
    """An unconditional return between free and a later line means the line is unreachable: no UAF."""
    src = """
    void f(obj_t* p) {
        free(p->buf);
        return;
        use(p->buf->x);
    }
    """
    assert not find_lifecycle_bugs(src)


def test_conditional_return_does_not_sever_real_uaf():
    """A guarded `if (e) return;` does NOT sever: a following deref of the freed ptr is a real UAF."""
    src = """
    void f(obj_t* p, int e) {
        free(p);
        if (e) return;
        p->x = 1;
    }
    """
    assert any(b.kind == "use-after-free" for b in find_lifecycle_bugs(src))


def test_array_element_then_array_free_not_double_free():
    """free(arr[i]) (element) then free(arr) (the array) are distinct objects, not a double-free."""
    src = """
    void f(coll_t* c) {
        for (int i = 0; i < c->n; i++)
            freerdp_addin_argv_free(c->arr[i]);
        free((void*)c->arr);
        c->arr = NULL;
    }
    """
    assert not any(b.kind == "double-free" for b in find_lifecycle_bugs(src))


def test_destructor_subfree_of_member_not_uaf():
    """Inside a destructor, a *_free wrapper on the argument is a sub-destructor of its members, not a
    dangle of the argument; following member frees are not UAF."""
    src = """
    void settings_free_internal(settings_t* settings) {
        freerdp_capability_data_free(settings, 0, TRUE);
        free(settings->ReceivedCapabilityDataSizes);
        settings->ReceivedCapabilityDataSizes = NULL;
    }
    """
    assert not find_lifecycle_bugs(src)


def test_context_handle_free_not_uaf():
    """png_free(ctx, obj) frees obj; ctx (the allocator handle) is used again legitimately."""
    src = """
    void f(png_t* png_ptr, info_t* info_ptr) {
        png_free(png_ptr, row_pointers);
        png_destroy_write_struct(&png_ptr, &info_ptr);
    }
    """
    assert not find_lifecycle_bugs(src)


def test_cpp_branch_frees_not_double_free():
    """Platform #if/#else arms each freeing the same ptr are exclusive, not a double-free."""
    src = """
    void f(void* buffer) {
    #ifdef A
        a_backtrace_free(buffer);
    #else
        b_backtrace_free(buffer);
    #endif
    }
    """
    assert not any(b.kind == "double-free" for b in find_lifecycle_bugs(src))
