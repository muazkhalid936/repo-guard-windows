"""RepoGuard PC scan for Windows: things that start automatically, running programs, and risky folders.

  pc_agent.py scan  [--backup DIR]
  pc_agent.py clean [--backup DIR] --ids ID [ID ...]

scan looks at:
  * the Startup folders, the registry Run / RunOnce keys and Scheduled Tasks: what each one runs,
    and whether it runs a known malware command or a script from a temp or public folder
  * PowerShell profiles and Git Bash startup files (.bashrc, .bash_profile)
  * VS Code / Cursor user settings and tasks that run code when a folder opens
  * the global git config (a foreign hooks folder, an ssh or fsmonitor program, shell aliases)
  * running processes: crypto-miners, known malware commands, scripts started from temp folders
  * scripts dropped in %TEMP% and C:\\Users\\Public

Every startup item is also listed in "inventory", so any of them can be turned off.
clean re-checks each id and fixes only those. Everything removed is copied to the backup folder first.
Items that need administrator rights come back with needs_admin=true. Prints JSON.
Reads only: it never runs anything it finds.
"""
import argparse, datetime, hashlib, importlib.util, json, os, re, shutil, stat, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location("rgpc_" + name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


engine = _load("engine")
cleaner = _load("cleaner")
RULES = engine.Rules(os.path.join(HERE, "rules.json"))
cleaner.RULES = RULES

IS_WIN = os.name == "nt"
TESTING = bool(os.environ.get("REPOGUARD_TEST_HOME"))
HOME = os.environ.get("REPOGUARD_TEST_HOME") or os.path.expanduser("~")


def _dir(var, *under_home):
    if TESTING or not os.environ.get(var):
        return os.path.join(HOME, *under_home)
    return os.environ[var]


APPDATA = _dir("APPDATA", "AppData", "Roaming")
LOCALAPPDATA = _dir("LOCALAPPDATA", "AppData", "Local")
TEMP = os.path.join(HOME, "AppData", "Local", "Temp") if TESTING else tempfile.gettempdir()
PUBLIC = os.environ.get("PUBLIC", r"C:\Users\Public")
PROGRAMDATA = os.environ.get("ProgramData", r"C:\ProgramData")
NO_WINDOW = engine.NO_WINDOW

# RepoGuard's own files hold the malware signatures, so never report them.
SELF_DIRS = {os.path.normcase(os.path.realpath(p)) for p in
             [os.path.dirname(HERE), getattr(sys, "_MEIPASS", ""), os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else ""] if p}

BAD_CMD = re.compile(
    r"powershell(?:\.exe)?\"?[^\n]*\s-(?:e|ec|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{24,}"
    r"|\b(?:iex|invoke-expression)\b[^\n]*(?:downloadstring|downloaddata|invoke-webrequest|\biwr\b|\birm\b|invoke-restmethod|net\.webclient)"
    r"|(?:downloadstring|invoke-webrequest|\biwr\b|\birm\b|invoke-restmethod)[^\n|]*\|\s*(?:iex|invoke-expression)\b"
    r"|mshta(?:\.exe)?\"?\s+[\"']?(?:https?|javascript|vbscript):"
    r"|certutil(?:\.exe)?\"?\s+[^\n]*-urlcache[^\n]*https?:"
    r"|regsvr32(?:\.exe)?\"?\s+[^\n]*/i:https?:"
    r"|bitsadmin(?:\.exe)?\"?\s+[^\n]*/transfer"
    r"|(?:curl|wget)[^|;&\n]*\|\s*(?:ba|z|da)?sh\b"
    r"|\bnode(?:\.exe)?\"?\s+\S*(?:[\\/]|\b)init\b"
    r"|\.orc\b|fa-brand-400|fa-solid-400\.woff2"
    r"|xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|stratum\+tcp|nicehash|cryptonight"
    r"|ethplorer|eth_getTransactionByHash|jsonkeeper\.com|npoint\.io", re.I)
ODD_CMD = re.compile(
    r"-w(?:indowstyle)?\s+hidden.*(?:http|\\temp\\|\\public\\)"
    r"|rundll32(?:\.exe)?\"?\s+[^\n]*javascript:"
    r"|\bcmd(?:\.exe)?\"?\s+/c\s+start\s+/min\b"
    r"|python[0-9.]*(?:\.exe)?\"?\s+-c\s+['\"].*(?:urllib|socket)", re.I)
MINERS = re.compile(r"xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|nicehash|nbminer|t-rex|phoenixminer|lolminer|gminer", re.I)
REMOTE_TOOLS = re.compile(r"anydesk|teamviewer|hoptodesk|rustdesk|screenconnect|connectwise|splashtop|logmein|remotepc|ammyy|supremo|dwservice|meshagent|ultraviewer", re.I)
INTERPRETERS = re.compile(r"(?:^|[\\/])(?:node|nodejs|python[0-9.]*|pythonw|py|wscript|cscript|powershell|pwsh|cmd|mshta|bash|sh|perl|ruby|bun|deno)(?:\.exe)?$", re.I)
SCRIPT_EXT = (".js", ".cjs", ".mjs", ".jse", ".py", ".pyw", ".vbs", ".vbe", ".ps1", ".psm1", ".bat", ".cmd", ".hta", ".wsf", ".sh", ".orc")


def finding(kind, path, detail, severity, fix, **extra):
    raw = f"{kind}|{path}|{extra.get('line', '')}|{extra.get('pid', '')}|{extra.get('cmd', '')}|{extra.get('label', '')}"
    fid = hashlib.sha1(raw.encode()).hexdigest()[:16]
    return dict(id=fid, kind=kind, path=path, detail=detail, severity=severity, fix=fix, **extra)


def read(path, limit=2_000_000):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


def run(args, timeout=60):
    try:
        r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, creationflags=NO_WINDOW)
        return r.returncode, r.stdout.decode("utf8", "replace"), r.stderr.decode("utf8", "replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


def powershell(script, timeout=90):
    """Runs a fixed, read-only PowerShell query and returns its JSON output (a list)."""
    rc, out, err = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script], timeout=timeout)
    if rc:
        raise RuntimeError(err.strip()[-300:] or f"PowerShell failed ({rc})")
    if not out.strip():
        return []  # e.g. no scheduled tasks outside \\Microsoft\\
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


def norm(p):
    return os.path.normcase(os.path.realpath(os.path.expandvars(p))) if p else ""


def is_self(p):
    n = norm(p)
    return any(n == d or n.startswith(d + os.sep) for d in SELF_DIRS)


def risky_place(p):
    if not p:
        return None
    n = norm(p)
    temps = {norm(TEMP), norm(os.path.join(LOCALAPPDATA, "Temp"))} | ({norm(r"C:\Windows\Temp")} if IS_WIN else set())
    for t in temps:
        if n.startswith(t + os.sep):
            return "a temp folder"
    if not TESTING and n.startswith(norm(PUBLIC) + os.sep):
        return "the Public folder"
    for root in (APPDATA, LOCALAPPDATA, PROGRAMDATA):
        if os.path.dirname(n) == norm(root):
            return "the top of " + os.path.basename(root)  # programs belong in a subfolder there
    return None


TOKEN = re.compile(r'"([^"]*)"|(\S+)')


def split_cmd(cmd):
    return [m.group(1) if m.group(1) is not None else m.group(2) for m in TOKEN.finditer(cmd or "")]


def script_of(args):
    """For `node C:\\x\\y.js ...` style commands, the script that actually runs."""
    if not args or not INTERPRETERS.search(args[0]):
        return None
    skip = False
    for a in args[1:]:
        low = a.lower()
        if skip:
            skip = False
            continue
        if low in ("-c", "-e", "--eval", "-command", "/c", "/k", "-encodedcommand", "-enc"):
            # cmd /c X: X is what runs
            if low in ("/c", "/k"):
                continue
            return None
        if low in ("-m", "-w", "-x", "--require", "-r", "-executionpolicy", "-windowstyle", "//e:jscript", "-file"):
            skip = low not in ("-file",)
            continue
        if a.startswith(("-", "/", "//")) and not os.path.isabs(a):
            continue
        return os.path.expandvars(a)
    return None


def judge(cmd, label=""):
    """(why, severity) for a command that starts automatically, or (None, None)."""
    args = split_cmd(cmd)
    prog = os.path.expandvars(args[0]) if args else ""
    script = script_of(args)
    target = script or prog
    if BAD_CMD.search(cmd) or MINERS.search(cmd):
        return "runs a known malware command", "block"
    if script and os.path.isfile(script):
        data = read(script, RULES.max)
        hits = [h for h in RULES.check(script.replace("\\", "/"), data) if h[1] == "block"]
        if hits or BAD_CMD.search((data or b"").decode("utf8", "replace")):
            return "runs a script with malware in it", "block"
    place = risky_place(target)
    if place and (script or not prog.lower().endswith(".exe")):
        return f"runs a script from {place}", "block"
    if place:
        return f"runs a program from {place}", "block"
    if ODD_CMD.search(cmd):
        return "runs an unusual hidden command", "review"
    if REMOTE_TOOLS.search(cmd + " " + label):
        return "remote-control software that starts automatically. Keep it only if you use it", "review"
    if prog and os.path.isabs(prog) and not os.path.exists(prog):
        return "points at a program that no longer exists", "review"
    return None, None


# ---------------------------------------------------------------- startup folder

def startup_dirs():
    dirs = [(os.path.join(APPDATA, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), False)]
    if not TESTING:
        dirs.append((os.path.join(PROGRAMDATA, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"), True))
    return dirs


def lnk_targets(paths):
    if not IS_WIN or not paths:
        return {}
    lst = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
    try:
        rows = powershell(f"$s=New-Object -ComObject WScript.Shell; @({lst}) | ForEach-Object {{ $l=$s.CreateShortcut($_); "
                          f"[pscustomobject]@{{p=$_; t=$l.TargetPath; a=$l.Arguments}} }} | ConvertTo-Json -Compress")
    except Exception:
        return {}
    return {r["p"]: ((r.get("t") or "") + (" " + r["a"] if r.get("a") else "")) for r in rows}


def scan_startup(out, inventory, errors):
    for d, admin in startup_dirs():
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        paths = [os.path.join(d, n) for n in names if n.lower() != "desktop.ini"]
        targets = lnk_targets([p for p in paths if p.lower().endswith(".lnk")])
        for p in paths:
            n = os.path.basename(p)
            if p.lower().endswith(".lnk"):
                cmd = targets.get(p, "")
                why, sev = judge(cmd, n) if cmd else (None, None)
            else:
                cmd = p
                data = read(p, RULES.max) or b""
                text = data.decode("utf8", "replace")
                hits = [h for h in RULES.check(n, data) if h[1] == "block"]
                why, sev = None, None
                if hits or BAD_CMD.search(text) or MINERS.search(text):
                    why, sev = "startup script with a known malware command", "block"
                elif n.lower().endswith(SCRIPT_EXT):
                    for line in text.splitlines():
                        w, s = judge(line.strip(), n)
                        if w:
                            why, sev = "startup script that " + w, s
                            break
            item = dict(id=finding("startup", p, "", "", "", label=n)["id"], label=n, path=p, program=cmd, command=cmd[:400],
                        where="Startup folder" + (" (all users)" if admin else ""), root=admin,
                        changed=datetime.datetime.fromtimestamp(os.lstat(p).st_mtime).strftime("%Y-%m-%d"))
            inventory.append(item)
            if why:
                out.append(finding("startup", p, f"{n}: {why}." + (f" Runs: {cmd[:220]}" if cmd != p else ""), sev,
                                   "move it out of the Startup folder (backed up)", label=n, root=admin, item=item["id"]))


# ---------------------------------------------------------------- registry Run keys

RUN_KEYS = [("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"), ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"), ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")]


def _hive(name):
    import winreg
    return winreg.HKEY_CURRENT_USER if name == "HKCU" else winreg.HKEY_LOCAL_MACHINE


def run_values():
    if not IS_WIN or TESTING:
        return
    import winreg
    for hive, key in RUN_KEYS:
        try:
            k = winreg.OpenKey(_hive(hive), key)
        except OSError:
            continue
        with k:
            i = 0
            while True:
                try:
                    name, value, typ = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                yield hive, key, name, str(value), typ


def scan_run_keys(out, inventory, errors):
    for hive, key, name, value, typ in run_values():
        path = f"{hive}\\{key}\\{name}"
        label = name or "(Default)"
        item = dict(id=finding("runkey", path, "", "", "", label=label)["id"], label=label, path=path, program=value, command=value[:400],
                    where=f"Registry {'RunOnce' if key.endswith('RunOnce') else 'Run'} ({'all users' if hive == 'HKLM' else 'you'})",
                    root=hive == "HKLM", changed="", hive=hive, key=key, name=name)
        inventory.append(item)
        why, sev = judge(value, label)
        if why:
            out.append(finding("runkey", path, f"{label}: {why}. Runs: {value[:220]}", sev, "delete this startup entry (backed up)",
                               label=label, root=hive == "HKLM", item=item["id"], hive=hive, key=key, name=name))


# ---------------------------------------------------------------- scheduled tasks

def scheduled_tasks():
    if not IS_WIN or TESTING:
        return []
    rows = powershell("Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | ForEach-Object { "
                      "[pscustomobject]@{path=$_.TaskPath; name=$_.TaskName; state=[string]$_.State; author=$_.Author; "
                      "actions=@($_.Actions | ForEach-Object { ([string]$_.Execute + ' ' + [string]$_.Arguments).Trim() }) } } "
                      "| ConvertTo-Json -Compress -Depth 4")
    return [r for r in rows if r]


def scan_tasks(out, inventory, errors):
    try:
        tasks = scheduled_tasks()
    except Exception as e:
        errors.append(f"Couldn't read Scheduled Tasks: {e}")
        return
    for t in tasks:
        full = (t.get("path") or "\\") + (t.get("name") or "")
        cmd = " && ".join(a for a in (t.get("actions") or []) if a)
        item = dict(id=finding("task", full, "", "", "", label=full)["id"], label=full, path=full, program=cmd, command=cmd[:400],
                    where="Scheduled Task", root=False, changed="", state=t.get("state", ""), author=t.get("author") or "")
        inventory.append(item)
        for a in t.get("actions") or []:
            why, sev = judge(a, full)
            if why:
                out.append(finding("task", full, f"Task {full}: {why}. Runs: {a[:220]}", sev, "delete the task (exported to the backup)",
                                   label=full, item=item["id"]))
                break


# ---------------------------------------------------------------- shell profiles, editors, git config

def profile_files():
    docs = [os.path.join(HOME, "Documents")] + ([] if TESTING else [os.path.join(HOME, "OneDrive", "Documents")])
    files = [os.path.join(HOME, n) for n in (".bashrc", ".bash_profile", ".profile")]
    for d in docs:
        for sub in ("WindowsPowerShell", "PowerShell"):
            for n in ("profile.ps1", "Microsoft.PowerShell_profile.ps1", "Microsoft.VSCode_profile.ps1"):
                files.append(os.path.join(d, sub, n))
    return files


def scan_profiles(out):
    for p in profile_files():
        data = read(p)
        if data is None:
            continue
        for i, line in enumerate(data.decode("utf8", "replace").splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if BAD_CMD.search(s):
                out.append(finding("shell", p, f"line {i}: {s[:220]}", "block", "remove this line", line=line.rstrip("\r")))
            elif ODD_CMD.search(s):
                out.append(finding("shell", p, f"line {i}: {s[:220]}", "review", "remove this line", line=line.rstrip("\r")))


EDITOR_DIRS = ["Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium"]


def scan_editors(out):
    content_ids = {r["id"] for r in RULES.content_rules}
    for ed in EDITOR_DIRS:
        for n in ("settings.json", "tasks.json"):
            p = os.path.join(APPDATA, ed, "User", n)
            data = read(p)
            if data is None:
                continue
            hits = [h for h in RULES.check(".vscode/" + n, data) if h[0] in content_ids]
            if hits:
                sev = "block" if any(h[1] == "block" and h[0] != "autorun" for h in hits) else "review"
                out.append(finding("file", p, f"{ed} {n}: " + ", ".join(sorted({h[2] for h in hits})), sev,
                                   "cut out the setting", rules=[list(h) for h in hits], rel=".vscode/" + n))


def scan_git_config(out, own_hooks):
    p = os.path.join(HOME, ".gitconfig")
    data = read(p)
    if data is None:
        return
    section = ""
    for i, line in enumerate(data.decode("utf8", "replace").splitlines(), 1):
        s = line.strip()
        m = re.match(r"\[([^\]\s\"]+)", s)
        if m:
            section = m.group(1).lower()
            continue
        if "=" not in s or s.startswith(("#", ";")):
            continue
        k, v = (x.strip() for x in s.split("=", 1))
        k = k.lower()
        why, sev = None, "review"
        if section == "alias" and v.lstrip('"').startswith("!") and BAD_CMD.search(v):
            why, sev = f"git alias '{k}' runs a known malware command", "block"
        elif section == "core" and k == "hookspath" and own_hooks and norm(v) != norm(own_hooks):
            why = f"git runs hooks from {v} for every repo"
        elif section == "core" and k in ("sshcommand", "fsmonitor") and v.lower() not in ("false", "true", "ssh", ""):
            why = f"git runs {v} automatically ({k})"
        if why:
            out.append(finding("gitconfig", p, f"line {i}: {why}", sev, "review by hand: git config --global --edit", line=s))


# ---------------------------------------------------------------- risky folders

def scan_temp_scripts(out):
    tops = [(TEMP, 4)] + ([] if TESTING else [(PUBLIC, 3)])
    seen = set()
    for top, depth in tops:
        top = os.path.realpath(top)
        if top in seen or not os.path.isdir(top):
            continue
        seen.add(top)
        base = top.count(os.sep)
        for cur, dirs, names in os.walk(top, followlinks=False):
            if cur.count(os.sep) - base >= depth:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "pip", "go-build") and not d.startswith(("_MEI", "repoguard-", "rg-"))
                       and not engine.QUARANTINE.search(d) and not is_self(os.path.join(cur, d))]
            for n in names:
                p = os.path.join(cur, n)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode) or st.st_size > 3_000_000 or st.st_size < 40:
                    continue
                head = read(p, 4096) or b""
                is_script = n.lower().endswith(SCRIPT_EXT) or head.startswith(b"#!")
                data_file = n.lower().endswith((".json", ".jsonl", ".txt", ".md", ".log", ".html", ".htm", ".csv", ".map", ".xml", ".yml", ".yaml", ".etl", ".tmp"))
                if not is_script and not data_file and b"\0" not in head[:1024] and re.search(rb"require\(|import |eval\(|exec\(|child_process|subprocess", head):
                    is_script = True  # script content without an extension
                if not is_script:
                    continue
                data = read(p, RULES.max)
                hits = [h for h in RULES.check(p.replace("\\", "/"), data) if h[1] == "block"]
                text = (data or b"").decode("utf8", "replace")
                if hits or BAD_CMD.search(text):
                    what = ", ".join(sorted({h[2] for h in hits})) or "known malware command"
                    out.append(finding("tempfile", p, f"script in {risky_place(p) or 'a temp folder'}: {what}", "block", "delete the file (backed up)"))


# ---------------------------------------------------------------- processes

def processes():
    if not IS_WIN or TESTING:
        return []
    rows = powershell("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine "
                      "| ConvertTo-Json -Compress")
    return [dict(pid=int(r.get("ProcessId") or 0), ppid=int(r.get("ParentProcessId") or 0), name=r.get("Name") or "",
                 exe=r.get("ExecutablePath") or "", cmd=r.get("CommandLine") or "") for r in rows]


def signed_ok(paths):
    """{path: True if Windows says its signature is valid}."""
    if not paths:
        return {}
    lst = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
    try:
        rows = powershell(f"@({lst}) | ForEach-Object {{ [pscustomobject]@{{p=$_; s=[string](Get-AuthenticodeSignature -LiteralPath $_).Status}} }} | ConvertTo-Json -Compress")
    except Exception:
        return {}
    return {r["p"]: r.get("s") == "Valid" for r in rows}


def scan_processes(out):
    me = {os.getpid(), os.getppid()}
    procs = processes()
    risky_exes = sorted({p["exe"] for p in procs if p["exe"] and risky_place(p["exe"])})
    signed = signed_ok(risky_exes)
    for pr in procs:
        if pr["pid"] in me or pr["pid"] < 5 or is_self(pr["exe"]):
            continue
        cmd, exe = pr["cmd"], pr["exe"]
        why, sev = None, "block"
        script = script_of(split_cmd(cmd))
        splace = risky_place(script) if script else None
        place = risky_place(exe)
        if MINERS.search(cmd) or MINERS.search(exe):
            why = "known crypto-miner"
        elif BAD_CMD.search(cmd):
            why = "runs a known malware command"
        elif splace and not is_self(script):
            why = f"runs a script from {splace}"
        elif place and not signed.get(exe, False):
            why = f"unsigned program running from {place}"
            sev = "review"  # installers and build tools run unsigned programs from temp folders too
        elif REMOTE_TOOLS.search(exe):
            why, sev = "remote-control software is running. Keep it only if you use it", "review"
        if why:
            out.append(finding("process", exe or pr["name"], f"PID {pr['pid']} {pr['name']}: {why}: {cmd[:220]}", sev,
                               "stop the process" + (" and quarantine its script" if splace else ""), pid=pr["pid"], cmd=cmd[:500]))


# ---------------------------------------------------------------- clean

class NeedsAdmin(Exception):
    pass


class Fixer:
    def __init__(self, backup):
        stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.backup_dir = os.path.join(backup, "pc-" + stamp)

    def _dest(self, path, suffix=".quarantined"):
        drive, rest = os.path.splitdrive(path)
        dst = os.path.join(self.backup_dir, (drive.replace(":", "") + rest).lstrip("/\\") + suffix)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        return dst

    def backup(self, path):
        dst = self._dest(path, ".bak")
        shutil.copy2(path, dst)
        os.chmod(dst, stat.S_IREAD)
        return dst

    def quarantine(self, path):
        dst = self._dest(path)
        try:
            shutil.move(path, dst)
        except PermissionError:
            raise NeedsAdmin()
        try:
            os.chmod(dst, stat.S_IREAD)
        except OSError:
            pass
        return "moved to " + dst

    def remove_line(self, path, line):
        data = read(path)
        if data is None:
            return "already gone"
        text = data.decode("utf8", "replace")
        nl = "\r\n" if "\r\n" in text else "\n"
        lines = text.split(nl)
        kept = [l for l in lines if l.rstrip("\r") != line]
        if len(kept) == len(lines):
            return "line already gone"
        self.backup(path)
        with open(path, "w", encoding="utf8", newline="") as fh:
            fh.write(nl.join(kept))
        return "line removed"

    def runkey_off(self, f):
        import winreg
        dst = self._dest(f"{f['hive']}\\{f['key']}\\{f['name'] or 'Default'}", ".json")
        try:
            with winreg.OpenKey(_hive(f["hive"]), f["key"], 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
                value, typ = winreg.QueryValueEx(k, f["name"])
                with open(dst, "w", encoding="utf8") as fh:
                    json.dump({"hive": f["hive"], "key": f["key"], "name": f["name"], "value": value, "type": typ}, fh, indent=1)
                winreg.DeleteValue(k, f["name"])
        except FileNotFoundError:
            return "already gone"
        except PermissionError:
            raise NeedsAdmin()
        return "startup entry deleted; saved to " + dst

    def task_off(self, name):
        q = name.replace("'", "''")
        folder, _, leaf = name.rpartition("\\")
        folder = (folder + "\\") if folder else "\\"
        dst = self._dest("Tasks" + name, ".xml")
        rc, xml, err = run(["schtasks.exe", "/Query", "/TN", name, "/XML"])
        if rc:
            return "already gone" if "cannot find" in err.lower() else f"couldn't read the task: {err.strip()[-200:]}"
        with open(dst, "w", encoding="utf8") as fh:
            fh.write(xml)
        rc, o, err = run(["schtasks.exe", "/Delete", "/TN", name, "/F"])
        if rc:
            if "denied" in err.lower():
                raise NeedsAdmin()
            raise RuntimeError(err.strip()[-200:] or "couldn't delete the task")
        return "task deleted; exported to " + dst

    def fix(self, f, inv):
        k = f["kind"]
        if k == "startup":
            p = f["path"]
            return self.quarantine(p) if os.path.exists(p) else "already gone"
        if k == "runkey":
            item = inv.get(f.get("item") or f["id"], f)
            return self.runkey_off(item)
        if k == "task":
            return self.task_off(f.get("label") or f["path"])
        if k == "shell":
            return self.remove_line(f["path"], f["line"])
        if k == "tempfile":
            return self.quarantine(f["path"]) if os.path.exists(f["path"]) else "already gone"
        if k == "file":
            data = read(f["path"], RULES.max + 1)
            if data is None:
                return "already gone"
            hits = RULES.check(f.get("rel") or f["path"], data)
            if not hits:
                return "already clean"
            new, notes = cleaner.clean_text(f.get("rel") or f["path"], data, hits)
            self.backup(f["path"])
            if new is None:
                os.unlink(f["path"])
                return "deleted: " + "; ".join(notes)
            with open(f["path"], "wb") as fh:
                fh.write(new)
            return "cleaned: " + "; ".join(notes)
        if k == "process":
            pid = int(f["pid"])
            now = next((p for p in processes() if p["pid"] == pid), None)
            if not now:
                return "already stopped"
            if now["cmd"][:500] != f["cmd"]:
                return "PID now belongs to another program; left alone"
            rc, o, err = run(["taskkill.exe", "/PID", str(pid), "/T", "/F"])
            if rc:
                if "denied" in err.lower():
                    raise NeedsAdmin()
                raise RuntimeError(err.strip()[-200:])
            extra = ""
            script = script_of(split_cmd(now["cmd"]))
            if script and risky_place(script) and os.path.isfile(script):
                time.sleep(0.5)
                extra = "; script " + self.quarantine(script)
            return "stopped" + extra
        raise RuntimeError("review this one by hand")


def scan(own_hooks=""):
    out, inventory, errors = [], [], []
    for step in (lambda: scan_startup(out, inventory, errors), lambda: scan_run_keys(out, inventory, errors),
                 lambda: scan_tasks(out, inventory, errors), lambda: scan_profiles(out), lambda: scan_editors(out),
                 lambda: scan_git_config(out, own_hooks), lambda: scan_temp_scripts(out), lambda: scan_processes(out)):
        try:
            step()
        except Exception as e:  # one broken check shouldn't hide the others
            errors.append(f"{type(e).__name__}: {e}")
    return out, inventory, errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["scan", "clean"])
    ap.add_argument("--backup", default=os.path.join(LOCALAPPDATA, "RepoGuard", "quarantine"))
    ap.add_argument("--own-hooks", default="", help="RepoGuard's git hooks folder, so it isn't reported")
    ap.add_argument("--ids", nargs="*", default=[])
    a = ap.parse_args()
    cleaner.TMPDIR = tempfile.mkdtemp(prefix="repoguard-")
    info = {"host": os.environ.get("COMPUTERNAME", ""), "python": sys.version.split()[0]}
    findings, inventory, errors = scan(a.own_hooks)
    if a.mode == "scan":
        shutil.rmtree(cleaner.TMPDIR, ignore_errors=True)
        print(json.dumps({"info": info, "findings": findings, "inventory": inventory, "errors": errors[:50]}))
        return
    fx = Fixer(a.backup)
    by_id = {f["id"]: f for f in findings}
    inv = {i["id"]: i for i in inventory}
    for i in inventory:  # any startup item can be turned off from the list, not just flagged ones
        if i["id"] not in by_id:
            kind = "startup" if i["where"].startswith("Startup") else "runkey" if i["where"].startswith("Registry") else "task"
            by_id[i["id"]] = dict(i, kind=kind, item=i["id"])
    results = []
    for fid in a.ids:
        f = by_id.get(fid)
        if not f:
            results.append({"id": fid, "ok": True, "result": "no longer found"})
            continue
        try:
            results.append({"id": fid, "ok": True, "path": f.get("path") or f.get("label"), "result": fx.fix(f, inv)})
        except NeedsAdmin:
            results.append({"id": fid, "ok": False, "path": f.get("path") or f.get("label"), "result": "needs administrator rights: run RepoGuard as administrator", "needs_admin": True})
        except cleaner.Manual as e:
            results.append({"id": fid, "ok": False, "path": f.get("path"), "result": f"left unchanged: {e}"})
        except Exception as e:
            results.append({"id": fid, "ok": False, "path": f.get("path"), "result": f"failed: {e}"})
    shutil.rmtree(cleaner.TMPDIR, ignore_errors=True)
    after, inventory, errors = scan(a.own_hooks)
    print(json.dumps({"info": info, "results": results, "backup": fx.backup_dir, "findings": after, "inventory": inventory, "errors": errors[:50]}))


if __name__ == "__main__":
    main()
