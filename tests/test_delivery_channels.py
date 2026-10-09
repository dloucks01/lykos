"""Which channels a substrate can actually carry, and the inventory used to decide.

The channel ranking is universal by design: `modes_for` ends with every channel attempted, so a
wrong guess costs a retry rather than a miss. That is the right shape wherever all three channels
EXIST -- and three of them do not, on the substrate where an execution is dearest:

  * a wasm REACTOR module has no process, so there is no argv at all;
  * WASI is capability-based, so with no preopened directory a module cannot open a path even
    when it is handed the name;
  * the driver hardcoded `args: ['prog']`, so even a WASI COMMAND -- which does have argv --
    never saw an argument the sandbox passed.

`arg` was nevertheless ranked FIRST for every wasm target (no call edges, so the native ranking
fell through to its default), at 11 exec/s measured. A campaign spent its budget delivering input
nowhere before the multi-channel retry reached stdin, the one channel that worked.

The second half is the inventory those decisions read. `ingest.triage_symbols` returned only
`imports.symbols`, and for a wasm module the imports are its HOST CALL SURFACE: a `--no-entry`
reactor has none at all (measured: 0 imports, 2 exports). So no vocabulary, however complete,
could have seen a wasm module's names -- they are in `exports.symbols`. Both halves answer "what
does this target read", on either side of the boundary: the imports name the WASI calls it makes
(`fd_read`, `path_open`, `environ_get`) and the exports name its entry point (`_start`).
"""
import shutil
import subprocess

import pytest
from lykos.analyze import substrate
from lykos.analyze.poc.capture import MODES, modes_for

# A WASI COMMAND that reports what the host gave it, as four bytes on stdout: argc, the number of
# environment variables, the errno from asking for the first preopened directory, and the low byte
# of the environment's total BYTE SIZE (which moves with a VALUE, not just a name). Every one of
# them was a constant before this change: argc was always 1, the environment was always empty, and
# no directory was ever preopened (fd 3 -> EBADF).
_PROBE_WAT = """(module
  (import "wasi_snapshot_preview1" "args_sizes_get"
          (func $args (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "environ_sizes_get"
          (func $envs (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_prestat_get"
          (func $prestat (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
          (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (drop (call $args (i32.const 0) (i32.const 4)))
    (drop (call $envs (i32.const 8) (i32.const 12)))
    (i32.store8 (i32.const 16) (call $prestat (i32.const 3) (i32.const 64)))
    (i32.store8 (i32.const 32) (i32.load8_u (i32.const 0)))
    (i32.store8 (i32.const 33) (i32.load8_u (i32.const 8)))
    (i32.store8 (i32.const 34) (i32.load8_u (i32.const 16)))
    (i32.store8 (i32.const 35) (i32.load8_u (i32.const 12)))
    (i32.store (i32.const 40) (i32.const 32))
    (i32.store (i32.const 44) (i32.const 4))
    (drop (call $write (i32.const 1) (i32.const 40) (i32.const 1) (i32.const 48)))
  )
)
"""

# A REACTOR: no `_start`, one two-argument export. Nothing the host could hand it as argv.
_REACTOR_WAT = """(module
  (memory (export "memory") 1)
  (func (export "parse") (param i32 i32) (result i32) (i32.const 0))
)
"""


def _wat(tmp_path, name, src):
    w2w = shutil.which("wat2wasm")
    if not w2w:
        pytest.skip("wat2wasm not installed")
    s = tmp_path / f"{name}.wat"
    s.write_text(src)
    out = tmp_path / f"{name}.wasm"
    r = subprocess.run([w2w, str(s), "-o", str(out)], capture_output=True)
    assert r.returncode == 0, r.stderr.decode()
    return out


@pytest.fixture(scope="module")
def node():
    from lykos.analyze.dynamic.sandbox import _node
    n = _node()
    if not n:
        pytest.skip("no node to execute a WebAssembly module")
    return n


def _probe(exe, **kw):
    """(argc, env_count, prestat_errno, env_bytes_low) as the module itself observed them."""
    from lykos.analyze.dynamic import sandbox
    res = sandbox.run(exe, timeout=30, **kw)
    assert not sandbox.did_not_run(res.isolation), res.note
    assert len(res.stdout) >= 4, f"the module wrote {res.stdout!r}"
    return tuple(res.stdout[:4])


# ---- the channels the substrate can carry --------------------------------------------------

def test_a_wasm_reactor_is_offered_only_the_channel_it_has():
    """`arg` and `file` cannot reach a module with no process and no preopens, so they are not
    offered -- not a narrowing of the search: those executions found nothing by construction."""
    assert modes_for([], symbols=["parse [func]", "memory [mem]"], file_type="wasm") == ["stdin"]


def test_a_wasi_command_keeps_every_channel():
    """The opposite case, decided by the module rather than the format: `_start` means a real
    process, so argv, the environment and the host's preopens all exist."""
    got = modes_for([], symbols=["_start [func]", "memory [mem]"], file_type="wasm")
    assert set(got) == set(MODES)


def test_the_decoration_the_wasm_parser_adds_does_not_hide_the_entry_point():
    """The parser records `_start [func]`, so a plain membership test is False on every module
    that has one -- which would silently leave a WASI command with stdin only."""
    assert substrate.WASI_COMMAND_EXPORT in substrate.symbol_names(["_start [func]"])
    assert substrate.channels("wasm", ["_start [func]"]) != ("stdin",)


@pytest.mark.parametrize("ftype", ["elf", "pe", "jar", "class", "pyc", "dotnet"])
def test_every_other_executable_format_is_unrestricted(ftype):
    """A .NET assembly, a jar and a .pyc DO take argv and DO open files -- the argument is
    appended after the assembly/-jar/script and file mode passes a staged path. This narrowing
    is specific to the substrate that lacks the channel, not to managed targets in general."""
    assert set(substrate.channels(ftype)) >= set(MODES)
    assert set(modes_for([], file_type=ftype)) == set(MODES)


def test_an_untriaged_target_is_not_narrowed():
    """An empty file_type means triage has not run, not that nothing can be delivered."""
    assert set(modes_for([], file_type=None)) == set(MODES)
    assert set(modes_for([], file_type="")) == set(MODES)


def test_a_given_mode_still_wins_outright():
    assert modes_for([], given="arg", symbols=["parse [func]"], file_type="wasm") == ["arg"]


# ---- the WASI import surface is channel evidence -------------------------------------------

@pytest.mark.parametrize("imports,first", [
    (["wasi_snapshot_preview1.fd_read [func]"], "stdin"),
    (["wasi_snapshot_preview1.path_open [func]"], "file"),
    # Both: a program that opens a path AND reads a descriptor. `fd_read` is the interactive
    # primitive here exactly as read(2) is natively, so stdin breaks the tie.
    (["wasi_snapshot_preview1.fd_read [func]",
      "wasi_snapshot_preview1.path_open [func]"], "stdin"),
])
def test_a_modules_wasi_imports_say_which_channel_it_reads(imports, first):
    """A wasm module can only reach the outside world through an import it declares, which makes
    this the sharpest channel evidence any format here offers."""
    assert modes_for([], symbols=imports + ["_start [func]"], file_type="wasm")[0] == first


# ---- the inventory both of the above read --------------------------------------------------

class _FakeContent:
    def __init__(self, blob):
        self._blob = blob

    def get_bytes(self, _sha):
        return self._blob


def _symbols_from(rec):
    """`triage_symbols` over a triage record, without a database.

    `importlib`, not `from lykos.analyze import ingest`: the package exports a FUNCTION of that
    name, which shadows the module in its own namespace.
    """
    import importlib
    ing = importlib.import_module("lykos.analyze.ingest")
    orig = ing.triage_record
    try:
        ing.triage_record = lambda *a, **k: dict(rec)
        return ing.triage_symbols(None, None, None)
    finally:
        ing.triage_record = orig


def test_exports_are_part_of_the_inventory():
    """The gap itself: a reactor module's names live ONLY here, so reading imports alone made
    them unreachable to every consumer."""
    syms = _symbols_from({"imports": {"symbols": []},
                          "exports": {"symbols": ["parse [func]", "memory [mem]"]}})
    assert syms == ["parse [func]", "memory [mem]"]


def test_imports_come_first_and_duplicates_collapse():
    """Imports first because they answer "what does it READ"; a name on both sides is one name."""
    syms = _symbols_from({"imports": {"symbols": ["fd_read", "shared"]},
                          "exports": {"symbols": ["shared", "_start"]}})
    assert syms == ["fd_read", "shared", "_start"]


def test_a_record_with_neither_half_is_empty_not_an_error():
    assert _symbols_from({}) == []
    assert _symbols_from({"imports": None, "exports": None}) == []


# ---- end to end: the module reports what the host actually gave it ------------------------

def test_a_wasi_command_receives_the_argv_the_sandbox_passed(node, tmp_path):
    """`args` was hardcoded to ['prog'], so argc was 1 for every input ever delivered. The
    module reports its own argc, which is the only witness that cannot be faked here."""
    exe = _wat(tmp_path, "probe", _PROBE_WAT)
    assert _probe(exe)[0] == 1, "argv[0] alone when nothing is passed"
    assert _probe(exe, argv=["one", "two"])[0] == 3


def test_a_wasi_command_receives_the_environment_channel(node, tmp_path):
    """`env: {}` was hardcoded too, so `env_overrides` -- the environment as an input channel --
    could not reach a wasm module at all.

    Both runs set an override, so the ambient environment cancels out: the same variable carries
    a longer VALUE in the second, and the module reports the environment's total byte size. That
    the size moves by exactly the extra bytes is the claim -- the value arrived, not just a name.
    """
    exe = _wat(tmp_path, "probe", _PROBE_WAT)
    one = _probe(exe, env_overrides={"LYKOS_ENV_PROBE": "A"})
    many = _probe(exe, env_overrides={"LYKOS_ENV_PROBE": "A" * 65})
    assert one[1] == many[1], "the same single variable in both runs"
    assert (many[3] - one[3]) % 256 == 64


def test_file_delivery_preopens_the_directory_the_path_lives_in(node, tmp_path):
    """WASI grants filesystem access by capability: with no preopen, `path_open` cannot reach
    the file whatever its name, which is why `file` mode was impossible rather than merely
    unlikely. fd 3 is the first preopened descriptor; EBADF (8) means none was granted."""
    exe = _wat(tmp_path, "probe", _PROBE_WAT)
    inp = tmp_path / "input.bin"
    inp.write_bytes(b"A" * 16)
    assert _probe(exe)[2] != 0, "no path passed: nothing should be preopened"
    assert _probe(exe, argv=[str(inp)])[2] == 0


def test_the_reports_own_directory_is_never_granted_to_the_module(node, tmp_path):
    """The verdict is written to a FILE precisely because a target can write whatever it likes
    to stderr, and a mutator rewarded for crashes would learn to forge a marker there. Granting
    the report's directory would hand that back, so an argument naming it is refused.

    Driven through the driver directly, because that is the only way to choose the report path
    and then point an argument at it.
    """
    import json
    import subprocess as sp

    from lykos.analyze.dynamic import sandbox
    exe = _wat(tmp_path, "probe", _PROBE_WAT)
    rep = tmp_path / "reports" / "report.json"
    rep.parent.mkdir()
    ok = tmp_path / "elsewhere" / "input.bin"
    ok.parent.mkdir()
    ok.write_bytes(b"A")

    def drive(arg):
        rep.unlink(missing_ok=True)
        r = sp.run([node, "--no-warnings", sandbox._wasm_driver_path(), str(exe), str(rep), arg],
                   capture_output=True, timeout=60)
        assert json.loads(rep.read_text())["status"] == "clean", r.stderr.decode()[:300]
        return r.stdout[2]                     # the fd-3 prestat errno the module observed

    assert drive(str(ok)) == 0, "an ordinary path must be preopened"
    assert drive(str(rep)) != 0, "the report file's own directory must never be granted"
    assert drive(str(rep.parent)) != 0, "nor the directory itself"


def test_a_reactor_module_is_still_driven_by_the_bytes_in_its_memory(node, tmp_path):
    """The widening must not change the reactor path: it has no `_start`, so the input is staged
    in its linear memory and handed to the two-argument export, as before."""
    from lykos.analyze.dynamic import sandbox
    exe = _wat(tmp_path, "reactor", _REACTOR_WAT)
    res = sandbox.run(exe, stdin=b"A" * 64, argv=["ignored"], timeout=30)
    assert not res.crashed and not sandbox.did_not_run(res.isolation), res.note
