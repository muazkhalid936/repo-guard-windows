"""Scan engine and cleaner on Windows-style paths: detect, preview (changes nothing), approve, remove."""
import hashlib, os

from conftest import LOADER, PAD, core, git, infect, write


def snapshot(*dirs):
    h = hashlib.sha1()
    for d in dirs:
        for cur, ds, names in sorted(os.walk(d)):
            ds.sort()
            for n in sorted(names):
                p = os.path.join(cur, n)
                h.update(p.encode())
                with open(p, "rb") as fh:
                    h.update(fh.read())
    return h.hexdigest()


def setup_infected(tmp_path, remote):
    bare, dev = remote
    watch = tmp_path / "watch"
    git(tmp_path, "clone", "-q", str(bare), str(watch / "app"))
    infect(watch / "app")
    git(watch / "app", "add", "-A")
    git(watch / "app", "commit", "-qm", "c1")
    loose = watch / "loose"
    infect(loose)
    return watch


def engine(tmp_path, watch, mode="full"):
    return core("engine", mode, "--watch", str(watch), "--state", str(tmp_path / "state.json"),
                "--rules", os.path.join(os.path.dirname(__file__), "..", "repoguard", "core", "rules.json"), "--log", str(tmp_path / "log"))


RULES = os.path.join(os.path.dirname(__file__), "..", "repoguard", "core", "rules.json")


def test_engine_finds_the_worm(tmp_path, remote):
    watch = setup_infected(tmp_path, remote)
    rc, out, err = engine(tmp_path, watch)
    assert out, err
    paths = {f["path"] for f in out["active"]}
    assert {"init", "postcss.config.mjs", "package.json", ".gitignore"} <= paths
    assert all("\\" not in p for p in paths), "paths inside a project must use / on every system"


def test_engine_ignores_clean_code(tmp_path, remote):
    bare, dev = remote
    rc, out, err = engine(tmp_path, dev)
    assert out and out["active"] == [], err


def test_preview_changes_nothing_and_shows_the_code(tmp_path, remote):
    watch = setup_infected(tmp_path, remote)
    engine(tmp_path, watch)
    before = snapshot(watch)
    rc, plan, err = core("cleaner", "--state", str(tmp_path / "state.json"), "--rules", RULES, "--preview")
    assert rc == 0 and plan, err
    assert snapshot(watch) == before
    by = {(os.path.basename(i["repo"]), i["path"]): i for i in plan["items"]}
    pc = by[("loose", "postcss.config.mjs")]
    assert pc["action"] == "clean" and pc["kept"] == ["export default { plugins: {} };"]
    assert any("150 blank characters" in l for l in pc["removed"])
    assert by[("loose", "init")]["action"] == "delete"


def test_wrong_approval_is_refused(tmp_path, remote):
    watch = setup_infected(tmp_path, remote)
    engine(tmp_path, watch)
    before = snapshot(watch)
    rc, out, err = core("cleaner", "--state", str(tmp_path / "state.json"), "--rules", RULES, "--backup", str(tmp_path / "bk"),
                        "--expect", "0000000000000000")
    assert rc == 3
    assert snapshot(watch) == before


def test_approved_removal_cleans_and_backs_up_inside_the_backup_folder(tmp_path, remote):
    watch = setup_infected(tmp_path, remote)
    engine(tmp_path, watch)
    rc, plan, _ = core("cleaner", "--state", str(tmp_path / "state.json"), "--rules", RULES, "--preview")
    bk = tmp_path / "bk"
    rc, out, err = core("cleaner", "--state", str(tmp_path / "state.json"), "--rules", RULES, "--backup", str(bk),
                        "--log", str(tmp_path / "log"), "--expect", plan["fingerprint"])
    assert rc == 0 and out, err
    loose = watch / "loose"
    assert (loose / "postcss.config.mjs").read_text().strip() == "export default { plugins: {} };"
    assert not (loose / "init").exists()
    assert '"dev":"next dev"' in (loose / "package.json").read_text()
    assert (loose / ".gitignore").read_text().strip() == "node_modules"
    # every backup landed inside the backup folder (a C:\ path must not escape it)
    backups = [os.path.join(c, n) for c, _, ns in os.walk(bk) for n in ns]
    assert backups and all(os.path.abspath(b).startswith(os.path.abspath(str(bk))) for b in backups)
    rc, again, _ = engine(tmp_path, watch)
    assert again["active"] == []
