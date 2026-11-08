"""Per-finding potential-PoC generator."""
from lykos.analyze.potential_poc import generate

def test_injection_is_constructed_script():
    p = generate("f1", "CWE-22", "handle_path", "drivable", exported=False)
    assert ".." in p.trigger and "constructed" in p.reason

def test_exported_parser_shape_testable_now():
    p = generate("f2", "CWE-787", "rfx_process_message", "drivable", exported=True)
    assert p.testable_now and "build+run" in p.reason

def test_static_sink_needs_rebuild():
    p = generate("f3", "CWE-787", "audin_server_recv_formats", "drivable", exported=False)
    assert not p.testable_now and "expose_static" in p.recipe

def test_untainted_trigger_is_verification():
    p = generate("f4", "CWE-787", "rfx_differential_decode", "untainted", exported=True)
    assert "NOT attacker-controlled" in p.trigger
