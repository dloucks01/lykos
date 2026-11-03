"""Attack-path composition: chain multiple findings through the capability graph to an objective."""
from lykos.analyze import attack_path as ap


def test_leak_plus_write_composes_to_rce():
    """The canonical chain: an OOB read (leak) + an OOB write compose via technique edges to PC
    control and then RCE -- the multi-vuln path, each memory edge backed by a finding."""
    findings = [{"cwe": "CWE-125", "function": "disclose", "id": "f1"},
                {"cwe": "CWE-787", "function": "overflow", "id": "f2"}]
    path = ap.find_attack_path(findings)
    assert path.reached and path.objective == ap.RCE
    caps = path.gained_caps
    assert ap.LEAK in caps and ap.WRITE in caps and ap.PC in caps and ap.RCE in caps
    # the finding edges are present in the path
    cwes = [s.cwe for s in path.steps if s.cwe]
    assert "CWE-125" in cwes and "CWE-787" in cwes


def test_write_without_leak_does_not_reach_rce():
    """A write alone (no leak to defeat ASLR) stops short of PC control -- honest ceiling."""
    path = ap.find_attack_path([{"cwe": "CWE-787", "function": "w", "id": "f1"}])
    assert not path.reached
    assert ap.WRITE in path.gained_caps and ap.PC not in path.gained_caps


def test_command_injection_is_a_direct_objective():
    path = ap.find_attack_path([{"cwe": "CWE-78", "function": "run", "id": "f1"}])
    assert path.reached and path.objective == ap.CMD


def test_best_objective_is_chosen_rce_over_dos():
    """With both an RCE-capable chain and a DoS present, the path targets RCE."""
    findings = [{"cwe": "CWE-125", "function": "d", "id": "f1"},
                {"cwe": "CWE-787", "function": "o", "id": "f2"},
                {"cwe": "CWE-369", "function": "div", "id": "f3"}]
    path = ap.find_attack_path(findings)
    assert path.objective == ap.RCE


def test_poc_levels_annotate_edges():
    findings = [{"cwe": "CWE-125", "function": "d", "id": "f1"},
                {"cwe": "CWE-787", "function": "o", "id": "f2"}]
    pocs = [{"finding_id": "f2", "level": "L3"}]
    path = ap.find_attack_path(findings, pocs=pocs)
    lv = {s.cwe: s.level for s in path.steps if s.cwe}
    assert lv.get("CWE-787") == "L3"


def test_format_path_renders_entry_and_objective():
    path = ap.find_attack_path([{"cwe": "CWE-125", "id": "f1", "function": "d"},
                                {"cwe": "CWE-787", "id": "f2", "function": "o"}])
    txt = ap.format_path(path)
    assert txt.startswith("entry:") and "OBJECTIVE REACHED: rce" in txt


def test_no_findings_no_path():
    path = ap.find_attack_path([])
    assert not path.reached and path.steps == []
