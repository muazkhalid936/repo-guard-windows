"""Shared test setup: everything happens in temp folders with a private git config, so the tests never
touch your real git settings or RepoGuard data. The 'malware' here is harmless copies of its patterns."""
import json, os, shutil, subprocess, sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
PAD = " " * 150
LOADER = "var z = '-67" "52-3';"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    gcfg = tmp_path / "gitconfig"
    gcfg.write_text("[user]\n\tname = t\n\temail = t@t\n[init]\n\tdefaultBranch = main\n[protocol \"file\"]\n\tallow = always\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gcfg))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("REPOGUARD_SUPPORT", str(tmp_path / "support"))
    monkeypatch.setenv("SCAN_NO_NOTIFY", "1")
    monkeypatch.setenv("REPOGUARD_TEST", "1")
    monkeypatch.delenv("REPOGUARD_ALLOW_FETCH", raising=False)
    return tmp_path


def git(cwd, *args, check=True, env=None):
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, env=env)
    if check and p.returncode:
        raise AssertionError(f"git {' '.join(args)} failed: {p.stderr}")
    return p


def write(path, text):
    os.makedirs(os.path.dirname(str(path)), exist_ok=True)
    with open(path, "w", encoding="utf8", newline="\n") as fh:
        fh.write(text)


def infect(d):
    """The worm's changes, as harmless look-alikes."""
    write(os.path.join(d, "postcss.config.mjs"), "export default { plugins: {} };" + PAD + LOADER + "\n")
    write(os.path.join(d, "package.json"), '{"name":"x","scripts":{"dev":"node in' 'it && next dev","build":"next build"}}\n')
    write(os.path.join(d, ".gitignore"), "node_modules\nconfig.bat\n")
    write(os.path.join(d, "init"), "x" + PAD + LOADER + "\n")


def clean_project(d):
    write(os.path.join(d, "postcss.config.mjs"), "export default { plugins: {} };\n")
    write(os.path.join(d, "package.json"), '{"name":"x","scripts":{"dev":"next dev","build":"next build"}}\n')
    write(os.path.join(d, ".gitignore"), "node_modules\n")
    write(os.path.join(d, "a.js"), "export const a = 1;\n")


@pytest.fixture
def remote(tmp_path):
    """A bare 'GitHub' repo with one clean commit, plus a developer clone that can push to it."""
    bare = tmp_path / "origin.git"
    git(tmp_path, "init", "-q", "--bare", "-b", "main", str(bare))
    dev = tmp_path / "dev"
    git(tmp_path, "clone", "-q", str(bare), str(dev))
    clean_project(dev)
    git(dev, "add", "-A")
    git(dev, "commit", "-qm", "c1")
    git(dev, "push", "-q", "origin", "main")
    return bare, dev


def core(name, *args, env=None):
    from repoguard import paths
    p = subprocess.run(paths.core_cmd(name) + list(args), capture_output=True, text=True, env=env)
    line = next((l for l in reversed(p.stdout.splitlines()) if l.startswith("{")), None)
    return p.returncode, (json.loads(line) if line else None), p.stderr
