"""Git protection: the hooks block an infected fetch, pull or clone before any file changes."""
import os

from conftest import git, infect
from repoguard import protect


def test_install_points_git_at_repoguard_hooks():
    ok, msg = protect.install()
    assert ok, msg
    assert protect.status() == "on"
    conf = open(os.path.join(protect.hooks_dir(), "repoguard.conf"), encoding="utf8").read()
    assert "rg_scan()" in conf and "gitscan" in conf
    for h in protect.HOOKS:
        assert b"\r\n" not in open(os.path.join(protect.hooks_dir(), h), "rb").read(), "hooks must keep LF line endings for sh"


def test_does_not_silently_replace_another_hooks_folder(tmp_path):
    git(tmp_path, "config", "--global", "core.hooksPath", str(tmp_path / "husky"))
    ok, msg = protect.install()
    assert not ok and protect.status() == "other"
    ok, msg = protect.install(force=True)
    assert ok and protect.status() == "on"
    protect.uninstall()
    assert protect.status() == "off"


def test_clean_pull_works_and_infected_pull_is_blocked(tmp_path, remote):
    bare, dev = remote
    assert protect.install()[0]
    me = tmp_path / "me"
    git(tmp_path, "clone", "-q", str(bare), str(me))
    # a clean change goes through
    (dev / "b.js").write_text("export const b = 2;\n")
    git(dev, "add", "-A"); git(dev, "commit", "-qm", "c2"); git(dev, "push", "-q", "origin", "main", env=dict(os.environ, REPOGUARD_ALLOW_FETCH="1"))
    git(me, "pull", "-q", "origin", "main")
    assert (me / "b.js").exists()
    # the worm pushes
    infect(dev)
    git(dev, "add", "-A"); git(dev, "commit", "-qm", "c2"); git(dev, "push", "-q", "origin", "main", env=dict(os.environ, REPOGUARD_ALLOW_FETCH="1"))
    head = git(me, "rev-parse", "HEAD").stdout
    p = git(me, "pull", "origin", "main", check=False)
    assert p.returncode != 0
    assert "BLOCKED" in p.stderr
    assert not (me / "init").exists()
    assert git(me, "rev-parse", "HEAD").stdout == head
    assert git(me, "fetch", check=False).returncode != 0
    # a fresh clone of the infected repo is refused too
    assert git(tmp_path, "clone", "-q", str(bare), str(tmp_path / "me2"), check=False).returncode != 0
    assert not (tmp_path / "me2" / "init").exists()
    # the override still works, for cleaning
    git(tmp_path, "clone", "-q", str(bare), str(tmp_path / "me3"), env=dict(os.environ, REPOGUARD_ALLOW_FETCH="1"))
    assert (tmp_path / "me3" / "init").exists()
