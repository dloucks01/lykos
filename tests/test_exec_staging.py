"""Scratch targets are staged and then EXECUTED, so the staging filesystem must allow exec. A
hardened / air-gapped box often mounts /tmp (and $TMPDIR) `noexec`, where `chmod +x` succeeds but
execve() returns EACCES -- the literal "executables were not executable" that silently killed a
whole engagement's dynamic pipeline. `JobContext.scratch()` must stage off a noexec tempdir onto a
lykos-owned exec-capable dir instead."""
import subprocess
import tempfile
from pathlib import Path

from lykos.jobs import context as C


def test_exec_capable_true_on_a_normal_dir(tmp_path):
    assert C._is_exec_capable(tmp_path) is True


def test_exec_capable_false_on_a_noexec_mount_simulated(tmp_path, monkeypatch):
    """We cannot mount noexec in a test, so prove the probe actually runs the file: a dir whose
    staged file cannot be executed (here: exec raising) reads as not exec-capable."""
    real_run = subprocess.run

    def fake_run(cmd, *a, **kw):
        if isinstance(cmd, list) and cmd and str(cmd[0]).endswith("/x"):
            raise OSError(13, "Permission denied")        # what a noexec execve looks like
        return real_run(cmd, *a, **kw)

    monkeypatch.setattr(C.subprocess, "run", fake_run)
    assert C._is_exec_capable(tmp_path) is False


class _FakeContent:
    def __init__(self, root):
        self.root = root


class _Ctx:
    """Minimal stand-in exercising the real scratch()/_scratch_base() methods."""
    _scratch_base = C.JobContext._scratch_base
    scratch = C.JobContext.scratch

    def __init__(self, root):
        self.content = _FakeContent(root)
        self.run_id = "deadbeef00"
        self._scratch = None


def test_scratch_uses_system_tempdir_when_it_allows_exec(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "_SYS_TMP_EXECOK", None)
    monkeypatch.setattr(C, "_is_exec_capable", lambda d: True)
    ctx = _Ctx(tmp_path)
    assert ctx._scratch_base() is None                    # None => default system tempdir
    assert str(ctx.scratch()).startswith(tempfile.gettempdir())


def test_scratch_relocates_off_a_noexec_tempdir_onto_the_case_store(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "_SYS_TMP_EXECOK", None)
    # System tempdir is noexec; the case-store filesystem is fine.
    sys_tmp = Path(tempfile.gettempdir()).resolve()

    # Only the system tempdir ROOT is noexec; any other dir is fine. Mirror the real helper's
    # side effect of creating the probed dir, so the chosen work dir exists for mkdtemp.
    def execok(d):
        if Path(d).resolve() == sys_tmp:
            return False
        Path(d).mkdir(parents=True, exist_ok=True)
        return True

    monkeypatch.setattr(C, "_is_exec_capable", execok)
    ctx = _Ctx(tmp_path)
    base = ctx._scratch_base()
    assert base is not None and base.startswith(str(tmp_path))     # relocated under content.root
    s = ctx.scratch()
    assert str(s).startswith(str(tmp_path))
