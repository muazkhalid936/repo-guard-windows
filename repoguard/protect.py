"""Git protection: RepoGuard's global git hooks, which block pulls, fetches and clones that bring malware.

install() writes the hooks into RepoGuard's data folder and points git's global core.hooksPath at it.
Git for Windows runs these sh hooks for the terminal, VS Code and GitHub Desktop alike.
"""
import os, shutil, subprocess
from . import paths

HOOKS = ["reference-transaction", "scan-common", "post-checkout", "post-merge", "post-rewrite"]
NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def hooks_dir():
    return paths.data("githooks")


def _git(*args):
    git = shutil.which("git")
    if not git:
        return 127, "", "Git isn't installed. Install Git for Windows first: https://git-scm.com/download/win"
    p = subprocess.run([git, *args], capture_output=True, text=True, creationflags=NO_WINDOW, cwd=os.path.expanduser("~"))
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def _sh_path(p):
    """C:\\Users\\x -> /c/Users/x, the form Git for Windows' sh understands."""
    p = os.path.abspath(p).replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        p = "/" + p[0].lower() + p[2:]
    return p


def _sh_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def _conf():
    scan = [*paths.core_cmd("gitscan")]
    note = [*paths.notify_cmd()]
    q = lambda cmd: " ".join(_sh_quote(_sh_path(c) if i == 0 or (os.path.isabs(c) and os.path.exists(c)) else c) for i, c in enumerate(cmd))  # noqa: E731
    return ("# Written by RepoGuard. How the hooks reach the scanner.\n"
            f"rg_scan() {{ {q(scan)} \"$@\"; }}\n"
            f"rg_notify() {{ {q(note)} \"$@\"; }}\n")


def current():
    rc, out, _ = _git("config", "--global", "--get", "core.hooksPath")
    return out if rc == 0 else ""


def _same(a, b):
    return bool(a and b) and os.path.normcase(os.path.abspath(os.path.expanduser(a))) == os.path.normcase(os.path.abspath(b))


def status():
    """'on', 'off', 'other' (core.hooksPath points somewhere else) or 'nogit'."""
    if not shutil.which("git"):
        return "nogit"
    cur = current()
    if not cur:
        return "off"
    if _same(cur, hooks_dir()) and all(os.path.exists(os.path.join(hooks_dir(), h)) for h in HOOKS):
        return "on"
    return "other" if not _same(cur, hooks_dir()) else "off"


def install(force=False):
    """Returns (ok, message)."""
    cur = current()
    if cur and not _same(cur, hooks_dir()) and not force:
        return False, (f"Git already uses hooks from {cur}. RepoGuard would replace that setting for every repo. "
                       "Choose Turn On Anyway if you don't need those hooks.")
    d = hooks_dir()
    os.makedirs(d, exist_ok=True)
    for h in HOOKS:
        with open(os.path.join(paths.HOOK_TEMPLATES, h), encoding="utf8") as src:
            body = src.read()
        with open(os.path.join(d, h), "w", encoding="utf8", newline="\n") as dst:
            dst.write(body)
        os.chmod(os.path.join(d, h), 0o755)
    with open(os.path.join(d, "repoguard.conf"), "w", encoding="utf8", newline="\n") as fh:
        fh.write(_conf())
    rc, _, err = _git("config", "--global", "core.hooksPath", d.replace("\\", "/"))
    if rc:
        return False, err or "git config failed"
    return True, "Git protection is on: pulls, fetches and clones that bring malware are blocked."


def uninstall():
    if _same(current(), hooks_dir()):
        _git("config", "--global", "--unset", "core.hooksPath")
    return True, "Git protection is off."
