"""Native Go/Rust injection-sink detection (lang_sinks) -- the detection half of P11.

lang_sinks must recognise Go and Rust binaries even when triage recorded no toolchain (common for a
static Rust/Go ELF), and must match the sink symbols as the CURRENT disassembler renders them
(rizin switched Rust `::` separators and renders trait-impl methods as `...Command>::do_exec`). These
are the version-fragile bits; the dynamic realization that turns a detected sink into an L3 PoC lives
in inject_stage and is covered by its own path (the finding here is the input to that)."""
from __future__ import annotations

import types

from lykos.analyze.detect.detectors import DetectContext, lang_sinks


def _edge(dst, src=0x1000, dst_addr=0x2000, site=0x1100):
    return types.SimpleNamespace(dst_name=dst, src_addr=src, dst_addr=dst_addr, site_addr=site)


def _ctx(edges, toolchain=""):
    return DetectContext(target_id="t", case_id="c", call_edges=edges, strings=[],
                         functions=[], func_irs={}, bits=64, arch="x86-64", toolchain=toolchain)


def _cwes(hits):
    return {h["cwe"] for h in hits}


def test_go_command_injection_detected_via_runtime_fallback():
    # no toolchain recorded; Go is recognised by the runtime.* edges, os_exec.Command is the sink
    edges = [_edge("runtime.main"), _edge("os_exec.Command"), _edge("os_exec._Cmd_.CombinedOutput")]
    assert "CWE-78" in _cwes(lang_sinks(_ctx(edges)))


def test_rust_command_injection_detected_via_mangling_signature():
    # no toolchain recorded; Rust is recognised by the ::h<hex> mangling, and the exec method is
    # rendered through the trait-impl form `...Command>::do_exec`
    edges = [
        _edge("core::panicking::panic::h0123456789abcdef"),
        _edge("std::sys::process::unix::unix::_<impl std::sys::process::unix::common::Command>"
              "::do_exec::h0867ea5afa3fe4e3"),
    ]
    assert "CWE-78" in _cwes(lang_sinks(_ctx(edges)))


def test_rust_file_sink_detected():
    edges = [_edge("std::rt::lang_start::h1111111111111111"),
             _edge("std::fs::File::open::h2222222222222222")]
    assert "CWE-22" in _cwes(lang_sinks(_ctx(edges)))


def test_clap_command_new_is_not_a_command_injection():
    # the clap arg-parser also has Command::new, which never execs -- keying on the EXEC methods
    # (spawn/do_exec/output/status), not construction, keeps this from being a false CWE-78 candidate
    edges = [_edge("std::rt::lang_start::h3333333333333333"),
             _edge("clap_builder::builder::command::Command::new::h4444444444444444")]
    assert "CWE-78" not in _cwes(lang_sinks(_ctx(edges)))


def test_plain_c_binary_is_not_treated_as_go_or_rust():
    # no go/rust signal -> lang_sinks declines entirely (the C detectors own these)
    edges = [_edge("sym.imp.strcpy"), _edge("main"), _edge("sym.imp.printf")]
    assert lang_sinks(_ctx(edges)) == []
