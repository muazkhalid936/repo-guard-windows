"""Where RepoGuard keeps its files, and how to start the core scripts."""
import os, sys

PKG = os.path.dirname(os.path.abspath(__file__))
FROZEN = getattr(sys, "frozen", False)
# Bundled data (core scripts, rules, hooks) lives next to the package, or in the PyInstaller folder.
BASE = os.path.join(getattr(sys, "_MEIPASS", ""), "repoguard") if FROZEN else PKG
CORE = os.path.join(BASE, "core")
HOOK_TEMPLATES = os.path.join(BASE, "githooks")
RULES = os.path.join(CORE, "rules.json")


def support_dir():
    d = os.environ.get("REPOGUARD_SUPPORT")
    if not d:
        root = os.environ.get("LOCALAPPDATA") if os.name == "nt" else os.path.expanduser("~/.local/share")
        d = os.path.join(root or os.path.expanduser("~"), "RepoGuard")
    os.makedirs(d, exist_ok=True)
    return d


def data(name):
    return os.path.join(support_dir(), name)


LOG = lambda: data("RepoGuard.log")  # noqa: E731


def cli_exe():
    """The console program that runs the core scripts (and the git hooks call).
    REPOGUARD_CLI points the tests at a built repoguard-cli.exe."""
    if os.environ.get("REPOGUARD_CLI"):
        return os.environ["REPOGUARD_CLI"]
    if FROZEN:
        return os.path.join(os.path.dirname(sys.executable), "repoguard-cli.exe")
    return None


def core_cmd(name):
    """Command that runs one core script with RepoGuard's own Python, isolated from the current folder."""
    exe = cli_exe()
    if exe:
        return [exe, "--core", name]
    return [sys.executable, "-I", "-X", "utf8", os.path.join(CORE, name + ".py")]


def notify_cmd():
    exe = cli_exe()
    if exe:
        return [exe, "notify"]
    return [sys.executable, "-I", "-X", "utf8", os.path.join(PKG, "cli.py"), "notify"]
