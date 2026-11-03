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
