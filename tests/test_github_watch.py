"""GitHub watch against a local fake GitHub: preview changes nothing; Fix only touches approved branches."""
import json, os, socket, subprocess, sys, time

import pytest

from conftest import LOADER, PAD, core, git, write

RULES = os.path.join(os.path.dirname(__file__), "..", "repoguard", "core", "rules.json")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def fake_github(tmp_path, monkeypatch):
    gh = tmp_path / "gh"
    bare = gh / "acme" / "app.git"
    git(tmp_path, "init", "-q", "--bare", "-b", "main", str(bare))
    work = tmp_path / "work"
    git(tmp_path, "clone", "-q", str(bare), str(work))
    write(work / "package.json", '{"name":"x","scripts":{"dev":"next dev"}}\n')
    git(work, "add", "-A"); git(work, "commit", "-qm", "c1"); git(work, "push", "-q", "origin", "main")
    for b in ("one", "two"):
        git(work, "checkout", "-q", "-b", b, "main")
        write(work / "init", "x" + PAD + LOADER + "\n")
        git(work, "add", "-A"); git(work, "commit", "-qm", b); git(work, "push", "-q", "origin", b)
    port = free_port()
    srv = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "mock_github.py"), str(port), str(gh)])
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    monkeypatch.setenv("REPOGUARD_GITHUB_API", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("REPOGUARD_GITHUB_TOKEN", "test")
    yield bare, tmp_path / "gw.json"
    srv.kill()


def test_preview_then_fix_only_the_approved_branch(fake_github, tmp_path):
    bare, state = fake_github
    rc, r, err = core("github_watch", "poll", "--rules", RULES, "--state", str(state))
    assert r and sorted(f["branch"] for f in r["findings"]) == ["one", "two"], err
    heads = {b: git(bare, "rev-parse", b).stdout for b in ("one", "two")}
    rc, plan, err = core("github_watch", "preview", "--rules", RULES, "--state", str(state))
    assert plan, err
    assert {b: git(bare, "rev-parse", b).stdout for b in ("one", "two")} == heads, "preview must not change GitHub"
    one = next(b for b in plan["branches"] if b["branch"] == "one")
    assert [(i["path"], i["action"]) for i in one["items"]] == [("init", "delete")]
    approved = tmp_path / "approved.json"
    approved.write_text(json.dumps([one["id"]]))
    rc, r, err = core("github_watch", "poll", "--rules", RULES, "--state", str(state), "--fix-existing", "--approved", str(approved))
    assert r, err
    assert [f["branch"] for f in r["fixed"]] == ["one"]
    assert "init" not in git(bare, "ls-tree", "--name-only", "one").stdout.split()
    assert git(bare, "rev-parse", "two").stdout == heads["two"], "an unapproved branch must not be touched"
