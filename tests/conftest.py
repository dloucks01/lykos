"""Test bootstrap: put `core/` on the path so `import lykos` works without install,
plus shared fixtures (DM-20)."""
import pathlib
import sys

_CORE = pathlib.Path(__file__).resolve().parent.parent / "core"
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

import pytest  # noqa: E402

from lykos.casestore import CaseStore  # noqa: E402


@pytest.fixture
def store(tmp_path):
    s = CaseStore.open(tmp_path / "case1")
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def case(store):
    return store.cases.create("demo")


import shutil  # noqa: E402
import subprocess  # noqa: E402

_C_SRC = (
    "#include <stdio.h>\n#include <string.h>\n"
    "int main(int argc,char**argv){char b[64];if(argc>1)strcpy(b,argv[1]);"
    "printf(\"%s\\n\",b);return 0;}\n"
)


@pytest.fixture(scope="session")
def gcc():
    exe = shutil.which("gcc") or shutil.which("cc")
    if not exe:
        pytest.skip("no C compiler available")
    return exe


@pytest.fixture(scope="session")
def sample_elf(gcc, tmp_path_factory):
    """A default-compiled x86-64 ELF for parser/stage tests."""
    d = tmp_path_factory.mktemp("elf")
    src = d / "m.c"
    src.write_text(_C_SRC)
    out = d / "default"
    subprocess.run([gcc, "-O2", str(src), "-o", str(out)], check=True,
                   capture_output=True)
    return out
