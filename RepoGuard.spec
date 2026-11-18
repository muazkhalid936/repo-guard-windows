# PyInstaller build: one folder with RepoGuard.exe (the app) and repoguard-cli.exe (core scripts and git hooks).
# Build on Windows: pyinstaller RepoGuard.spec
import os

HIDDEN = ["argparse", "base64", "datetime", "difflib", "hashlib", "importlib.util", "json", "re", "shutil", "stat",
          "subprocess", "tempfile", "time", "urllib.request", "urllib.parse", "urllib.error", "http.client", "ssl",
          "socket", "signal", "getpass", "runpy", "winreg", "ctypes", "html", "plistlib"]
DATAS = [("repoguard/core/*.py", "repoguard/core"), ("repoguard/core/rules.json", "repoguard/core"),
         ("repoguard/githooks/*", "repoguard/githooks")]
ICON = "build/RepoGuard.ico" if os.path.exists("build/RepoGuard.ico") else None

app_a = Analysis(["run_app.py"], datas=DATAS, hiddenimports=HIDDEN, excludes=["tkinter"])
cli_a = Analysis(["run_cli.py"], datas=DATAS, hiddenimports=HIDDEN, excludes=["tkinter", "PySide6"])
app_pyz = PYZ(app_a.pure)
cli_pyz = PYZ(cli_a.pure)
app_exe = EXE(app_pyz, app_a.scripts, [], exclude_binaries=True, name="RepoGuard", console=False, icon=ICON)
cli_exe = EXE(cli_pyz, cli_a.scripts, [], exclude_binaries=True, name="repoguard-cli", console=True, icon=ICON)
coll = COLLECT(app_exe, app_a.binaries, app_a.datas, cli_exe, cli_a.binaries, cli_a.datas, name="RepoGuard")
