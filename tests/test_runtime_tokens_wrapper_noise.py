"""Runtime comparison tokens (libtokencap) must be the TARGET's. The preload used to reach the
sandbox's own wrapper chain too -- bwrap's option parsing ('--unshare-user-try', ...) and setarch
('uname26', 'linux32', ...) were logged as 77 'runtime tokens' and fed to the fuzzing dictionary."""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze.dynamic import memoracle

_SRC = ('#include <string.h>\n#include <stdio.h>\n#include <unistd.h>\n'
        'int main(void){char b[64]={0}; read(0,b,63);'
        ' if(!strcmp(b,"OPEN-SESAME-77")) puts("in"); return 0;}\n')


@pytest.mark.skipif(memoracle.tokencap_lib() is None, reason="libtokencap not installed")
def test_runtime_tokens_are_the_targets_not_the_sandbox_wrappers(tmp_path, gcc):
    c = tmp_path / "t.c"; c.write_text(_SRC)
    exe = tmp_path / "t"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build fixture")
    toks = memoracle.runtime_tokens(str(exe), b"hello", host_arch="x86-64", target_arch="x86-64")
    assert b"OPEN-SESAME-77" in toks
    assert not any(t.startswith(b"--") for t in toks), toks       # bwrap's options
    assert not ({b"uname26", b"linux32", b"setarch"} & set(toks)), toks   # setarch's
