"""Embedded RTOS configuration audit — insecure FreeRTOSConfig.h settings.

These are absences of a defence declared in config, not code bugs, so the checks are about
reading config truthfully: a function-like configASSERT counts as defined, and the vendored
kernel's example configs must not be mistaken for the project's own.
"""
from __future__ import annotations

from pathlib import Path

from lykos.analyze.fingerprint import embedded_config as ec


def _cfg(tmp_path, body: str, rel="FreeRTOSConfig.h") -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return tmp_path


def _keys(root):
    return {f["dedup_key"] for f in ec.audit_tree(root)}


def test_flags_disabled_stack_overflow_check(tmp_path):
    root = _cfg(tmp_path, "#define configCHECK_FOR_STACK_OVERFLOW 0\n")
    assert "frtos-cfg:stackcheck" in _keys(root)


def test_enabled_stack_overflow_check_is_not_flagged(tmp_path):
    root = _cfg(tmp_path, "#define configCHECK_FOR_STACK_OVERFLOW 2\n"
                          "#define configASSERT( x ) if((x)==0){for(;;);}\n"
                          "#define portUSING_MPU_WRAPPERS 1\n"
                          "#define configUSE_MALLOC_FAILED_HOOK 1\n")
    assert "frtos-cfg:stackcheck" not in _keys(root)


def test_function_like_configASSERT_counts_as_defined(tmp_path):
    """The real gotcha: `#define configASSERT( x ) ...` has no space before '(', so a naive
    value parse misses it and reports it undefined."""
    root = _cfg(tmp_path, "#define configASSERT( x ) if( ( x ) == 0 ) { for(;;); }\n"
                          "#define configCHECK_FOR_STACK_OVERFLOW 2\n")
    assert "frtos-cfg:assert" not in _keys(root)


def test_missing_configASSERT_is_flagged(tmp_path):
    root = _cfg(tmp_path, "#define configUSE_PREEMPTION 1\n")
    assert "frtos-cfg:assert" in _keys(root)


def test_mpu_off_flagged_and_on_not(tmp_path):
    off = _cfg(tmp_path / "a", "#define configUSE_PREEMPTION 1\n")
    on = _cfg(tmp_path / "b", "#define configENABLE_MPU 1\n#define configASSERT( x )\n")
    assert "frtos-cfg:mpu" in _keys(off)
    assert "frtos-cfg:mpu" not in _keys(on)


def test_malloc_hook_only_flagged_with_dynamic_allocation(tmp_path):
    # hook off but STATIC allocation -> no dynamic alloc to fail, so not flagged
    static = _cfg(tmp_path / "s", "#define configSUPPORT_DYNAMIC_ALLOCATION 0\n"
                                  "#define configUSE_MALLOC_FAILED_HOOK 0\n"
                                  "#define configASSERT( x )\n")
    dynamic = _cfg(tmp_path / "d", "#define configSUPPORT_DYNAMIC_ALLOCATION 1\n"
                                   "#define configUSE_MALLOC_FAILED_HOOK 0\n"
                                   "#define configASSERT( x )\n")
    assert "frtos-cfg:mallocfail" not in _keys(static)
    assert "frtos-cfg:mallocfail" in _keys(dynamic)


def test_vendored_example_configs_are_ignored(tmp_path):
    """A kernel's example/template config must not be audited as the project's build config."""
    (tmp_path / "kernel/examples/template_configuration").mkdir(parents=True)
    (tmp_path / "kernel/examples/template_configuration/FreeRTOSConfig.h").write_text(
        "#define configUSE_PREEMPTION 1\n")        # no safety knobs at all
    # the project's OWN config is fully locked down
    (tmp_path / "FreeRTOSConfig.h").write_text(
        "#define configCHECK_FOR_STACK_OVERFLOW 2\n#define configENABLE_MPU 1\n"
        "#define configASSERT( x )\n#define configSUPPORT_DYNAMIC_ALLOCATION 0\n")
    assert _keys(tmp_path) == set(), "an example config leaked into the project audit"


def test_no_config_no_findings(tmp_path):
    (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
    assert ec.audit_tree(tmp_path) == []
