from harness.kb import KB
from harness.skills import SkillLibrary, augment_system
from harness.tools import ToolExecutor
from helpers import _cfg, _ctx, _fake_submitter


def test_loads_authored_skills():
    lib = SkillLibrary.load()
    names = lib.names()
    assert "heap-tcache" in names
    assert "sqli" in names
    assert "ret2libc" in names
    assert "tcache" in lib.get("heap-tcache").body.lower()


def test_get_is_case_insensitive_and_tolerant_of_suffix():
    lib = SkillLibrary.load()
    assert lib.get("Heap-Tcache") is not None
    assert lib.get("heap-tcache.md") is not None
    assert lib.get("does-not-exist") is None


def test_index_lists_names_with_when():
    lib = SkillLibrary.load()
    idx = lib.index()
    assert "heap-tcache" in idx
    assert "linux-privesc" in idx


def test_loads_from_explicit_dir(tmp_path):
    (tmp_path / "demo.md").write_text(
        "---\nname: demo-skill\nwhen: testing\n---\nDo the thing with `nmap`.\n"
    )
    lib = SkillLibrary.load(str(tmp_path))
    skill = lib.get("demo-skill")
    assert skill is not None
    assert "nmap" in skill.body
    assert skill.when == "testing"


def test_consult_skill_tool_loads_real_playbook():
    ex = ToolExecutor(_ctx(), KB(), _fake_submitter(), _cfg())
    out = ex.execute("consult_skill", {"name": "heap-tcache"})
    assert "SKILL: heap-tcache" in out
    assert "tcache" in out.lower()
    miss = ex.execute("consult_skill", {"name": "no-such-skill"})
    assert "no skill named" in miss


def test_augment_system_injects_index():
    ex = ToolExecutor(_ctx(), KB(), _fake_submitter(), _cfg())
    system = augment_system("BASE PROMPT", ex)
    assert "BASE PROMPT" in system
    assert "consult_skill" in system
    assert "heap-tcache" in system


def test_pivoting_skill_teaches_chisel_and_http_proxy():
    from harness.skills import SkillLibrary
    lib = SkillLibrary.load()
    skill = lib.get("pivoting")
    assert skill is not None
    body = skill.body.lower()
    assert "chisel" in body
    assert "record_host" in body
    assert "proxy" in body


def test_protocol_reversing_skill_present_and_clean():
    from harness.skills import SkillLibrary
    from harness import audit
    lib = SkillLibrary.load()
    s = lib.get("protocol-reversing")
    assert s is not None and "pwntools" in s.body.lower()
    assert audit.sentinel_violations() == []


# --- RE capability uplift (2026-09-12): emulation, unix sockets, deception ---

def test_protocol_reversing_teaches_emulation_and_unix_sockets():
    lib = SkillLibrary.load()
    body = lib.get("protocol-reversing").body.lower()
    # opaque parser / won't-run -> emulate the parser fn with unicorn (the example validator shortcut)
    assert "unicorn" in body
    assert "emulat" in body
    # probe ptrace before trusting a live attach
    assert "strace" in body
    # unix-domain socket auth + fd passing primitives
    assert "so_peercred" in body
    assert "scm_rights" in body
    # distrust the planted config; reconcile against the binary
    assert "decoy" in body
    assert "reconcile" in body


def test_protocol_reversing_pivots_to_emulation_on_obfuscation():
    # The example validator failure mode: the model hand-read a control-flow-FLATTENED parser,
    # mistook the flattener's dispatcher constants for command opcodes, fuzzed the
    # opcode space, and hit the same reject on every one. The skill must make
    # emulation the FIRST move on an obfuscation tell (not a fallback), name the
    # flattening trap, and teach the "same error on every opcode = wrong FRAME" pivot.
    lib = SkillLibrary.load()
    body = lib.get("protocol-reversing").body.lower()
    # names control-flow flattening as an obfuscation tell (don't hand-read it)
    assert "flatten" in body
    # the diagnostic: identical reject on every opcode = frame gate, not opcode space
    assert "same error" in body
    # emulate the exfiltrated binary directly — no daemon / delivery friction
    assert "no daemon" in body


def test_deception_awareness_skill_present_and_generic():
    from harness import audit
    lib = SkillLibrary.load()
    s = lib.get("deception-awareness")
    assert s is not None, "deception-awareness skill must exist"
    body = s.body.lower()
    assert "decoy" in body
    assert "ground truth" in body
    assert "reconcile" in body
    # it names the disproven-value discipline that reuses the KB
    assert "mark_dead" in body
    # naming a sentinel tool the image does not bake still fails the gate
    assert audit.sentinel_violations() == []


def test_pwntools_recipes_teach_unix_socket_ancillary():
    lib = SkillLibrary.load()
    body = lib.get("pwntools-recipes").body.lower()
    assert "so_peercred" in body
    assert "scm_rights" in body
    assert "sendmsg" in body


def test_pwn_triage_probes_ptrace_with_emulation_fallback():
    lib = SkillLibrary.load()
    body = lib.get("pwn-triage").body.lower()
    assert "strace" in body
    assert "emulat" in body


def test_firmware_re_hands_off_to_protocol_reversing():
    lib = SkillLibrary.load()
    body = lib.get("firmware-re").body.lower()
    assert "protocol-reversing" in body


# --- TOCTOU / double-fetch race (the example validator ROOT unlock, 2026-09-12) -------------------

def test_race_condition_toctou_skill_present_and_generic():
    from harness import audit
    lib = SkillLibrary.load()
    s = lib.get("race-condition-toctou")
    assert s is not None, "race-condition-toctou skill must exist"
    body = s.body.lower()
    # teaches the concurrent-flip exploit mechanics
    assert "memfd" in body
    assert "map_shared" in body
    assert "scm_rights" in body
    # names the recognisable signature: read twice, wants two values, flip while resubmitting
    assert "double-fetch" in body or "double fetch" in body
    assert "resubmit" in body or "flip" in body
    # it must NOT bake the box's real constants (mirrors the answer-key hygiene gate)
    assert audit.sentinel_violations() == []




def test_protocol_reversing_routes_a_double_fetch_to_the_race_skill():
    # the model's dead-end was reading --solve's "not field-solvable" as "build a hash
    # preimage". protocol-reversing must now route the double-fetch case to the race skill
    # instead, and say emulation cannot win a race.
    body = SkillLibrary.load().get("protocol-reversing").body.lower()
    assert "race-condition-toctou" in body
    assert "double-fetch" in body or "double fetch" in body
    assert "race" in body


def test_pwntools_recipes_teach_the_shared_memfd_race_primitive():
    body = SkillLibrary.load().get("pwntools-recipes").body.lower()
    assert "memfd" in body
    assert "map_shared" in body
