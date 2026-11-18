"""repoguard-cli: runs one core script (repoguard-cli --core engine full ...), or shows a warning box.

The app and the git hooks call this console program, so the scanners run in their own process.
"""
import os, runpy, sys

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from repoguard import paths  # noqa: E402

CORE_SCRIPTS = {"engine", "cleaner", "github_watch", "pc_agent", "gitscan"}


def notify(title, message):
    if os.name == "nt":
        import ctypes
        MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST = 0x30, 0x10000, 0x40000
        ctypes.windll.user32.MessageBoxW(None, message, "RepoGuard: " + title, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST)
    else:
        print(f"{title}: {message}", file=sys.stderr)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) >= 2 and argv[0] == "--core" and argv[1] in CORE_SCRIPTS:
        script = os.path.join(paths.CORE, argv[1] + ".py")
        sys.argv = [script] + argv[2:]
        runpy.run_path(script, run_name="__main__")
        return 0
    if len(argv) == 2 and argv[0] == "protect" and argv[1] in ("on", "off", "status"):
        from repoguard import protect
        if argv[1] == "status":
            print(protect.status())
            return 0
        ok, msg = protect.install() if argv[1] == "on" else protect.uninstall()
        print(msg)
        return 0 if ok else 1
    if len(argv) >= 3 and argv[0] == "notify":
        notify(argv[1], argv[2])
        return 0
    print("usage: repoguard-cli --core {engine,cleaner,github_watch,pc_agent,gitscan} ARGS...\n"
          "       repoguard-cli protect {on,off,status}\n"
          "       repoguard-cli notify TITLE MESSAGE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
