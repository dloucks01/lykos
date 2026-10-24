"""A directory bundle must never pull HOST files in through a symlink (analyze/ingest.py)."""
import importlib
import os
import shutil

ingest = importlib.import_module("lykos.analyze.ingest")


def test_symlink_out_of_the_bundle_is_not_a_dependency(tmp_path):
    secret = tmp_path / "host_secret"
    secret.write_text("TOPSECRET")
    b = tmp_path / "bundle"
    b.mkdir()
    shutil.copy("/bin/true", b / "chal")
    (b / "flag.txt").write_text("flag{x}")
    os.symlink(secret, b / "libc.so.6")
    os.symlink("flag.txt", b / "flag_link")              # inside: fine
    main, deps = ingest.gather_bundle(b)
    assert main is not None and main.name == "chal"
    assert "libc.so.6" not in deps
    assert "flag.txt" in deps and "flag_link" in deps


def test_elf_interp_reads_only_the_header(tmp_path):
    big = tmp_path / "huge.elf"
    with open("/bin/true", "rb") as src, open(big, "wb") as dst:
        dst.write(src.read())
        dst.truncate(64 << 20)                            # sparse 64 MiB tail
    is_elf, interp = ingest._elf_interp(big)
    assert is_elf
    assert interp is None or interp.startswith("/")
