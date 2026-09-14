"""The build-time capability gate: promise = mechanism, enforced offline."""
from harness import audit



def test_no_skill_names_an_unbaked_tool():
    violations = audit.sentinel_violations()
    assert violations == [], f"skills reference tools the image does not bake: {violations}"


def test_every_coverage_vector_maps_to_a_real_skill():
    gaps = audit.coverage_vector_skill_gaps()
    assert gaps == [], f"coverage vectors with no backing skill: {gaps}"


def test_promised_tools_include_the_baked_additions():
    # the things the harness Dockerfile adds beyond the base must be promised
    assert "linpeas.sh" in audit.PROMISED_TOOLS
    assert "pspy" in audit.PROMISED_TOOLS
    assert "gcc" in audit.PROMISED_TOOLS


def test_unbacked_sentinels_are_not_also_backed():
    assert not (set(audit.BACKED_SENTINELS) & set(audit.UNBACKED_SENTINELS))


def test_cve_corpus_is_generic_public_reference():
    # the corpus is generic public-CVE knowledge (like an offline exploit-db), not a
    # per-box answer key. Several real entries, and NO competition-box-specific CVE.
    count = audit.corpus_entry_count()
    assert count >= 12, f"CVE corpus has only {count} entries; expected a real spread"


def test_answer_key_leak_scanner_catches_a_synthetic_secret(tmp_path, monkeypatch):
    skills = tmp_path / "skills"
    corpus = tmp_path / "corpus"
    skills.mkdir()
    corpus.mkdir()
    monkeypatch.setattr(audit, "STRIPPED_SECRETS", ("synthetic-test-secret",))
    assert audit.answer_key_leaks(str(skills), str(corpus)) == []
    (skills / "example.md").write_text("synthetic-test-secret")
    assert audit.answer_key_leaks(str(skills), str(corpus))


def test_new_analysis_and_pivot_tools_are_promised():
    for t in ("radare2", "binwalk", "chisel", "proxychains"):
        assert t in audit.PROMISED_TOOLS, f"{t} must be promised (and baked)"


def test_chisel_is_now_backed_not_flagged():
    assert "chisel" in audit.BACKED_SENTINELS
    assert "chisel" not in audit.UNBACKED_SENTINELS
    assert audit.sentinel_violations() == []


# --- RE capability uplift (2026-09-12): emulator + qemu + python-module gate ---

def test_qemu_user_emulation_is_promised():
    # qemu-user-static gives foreign-arch/standalone-refusing binaries a way to run
    # (the firmware lane). If a skill tells the model to use it, the image must bake it.
    for t in ("qemu-x86_64-static", "qemu-aarch64-static"):
        assert t in audit.PROMISED_TOOLS, f"{t} must be promised (and baked)"


def test_promised_pymodules_cover_the_recipe_libs():
    # the RE recipes drive python_exec with these libs; the gate now covers modules,
    # not just $PATH tools, so a missing wheel fails the build instead of a live run.
    for m in ("pwn", "unicorn", "capstone"):
        assert m in audit.PROMISED_PYMODULES, f"{m} must be a promised python module"


def test_missing_promised_pymodules_detects_an_absent_module():
    # inject a fake importer: everything imports except unicorn.
    def importer(name):
        if name == "unicorn":
            raise ImportError("no unicorn")
        return object()
    missing = audit.missing_promised_pymodules(importer=importer)
    assert missing == ["unicorn"]


def test_missing_promised_pymodules_empty_when_all_present():
    missing = audit.missing_promised_pymodules(importer=lambda name: object())
    assert missing == []






def test_answer_constant_leak_scanner_catches_a_plant(tmp_path):
    # Prove the scanner actually fires, so a future leak fails the build (not a run).
    clean = tmp_path / "clean.py"; clean.write_text("X = 0xdeadbeef\n")
    leaky = tmp_path / "leak.py"; leaky.write_text("PREVIEW = 0x11223344  # synthetic fixture\n")
    assert audit.answer_constant_leaks(("11223344",), roots=[str(clean)]) == []
    hits = audit.answer_constant_leaks(("11223344",), roots=[str(clean), str(leaky)])
    assert hits and hits[0][1] == "11223344"
