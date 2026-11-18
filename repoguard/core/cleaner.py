"""RepoGuard cleaner: removes the malware parts that the scan engine found.

It cuts out only the injected code and keeps the rest of each file. A file is deleted
only when the whole file is the payload (.orc payloads, dropper .bat files, code disguised
as a font or image, a loader-only `init` or Python file).

Every original is copied to the backup folder first (read-only, with a .quarantined
suffix so nothing can run it). A rewritten file is syntax-checked before it is saved;
if the check fails the file is left as it is and reported for a manual look.

Git history:
  * origin/... copies of GitHub branches: a safe re-fetch (hooks, fsmonitor and pager off).
    A copy that is still infected afterwards is dropped; it is only a local cache.
  * local branches: moved to the clean upstream when the only difference is malware,
    otherwise a cleanup commit is added on top so no work is lost.
  * --permanent: also deletes infected tags and purges the unreachable infected commits.

  cleaner.py --state FILE --rules FILE --backup DIR --log FILE [--permanent] [--expect FINGERPRINT]
  cleaner.py --state FILE --rules FILE --preview   show every change first; changes nothing
Run with `python3 -I`. Prints a JSON summary.
"""
import argparse, datetime, difflib, hashlib, importlib.util, json, os, re, shutil, stat, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("rg_engine", os.path.join(HERE, "engine.py"))
engine = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(engine)

GIT_ENV = dict(engine.GIT_ENV)
SAFE = engine.GIT_BASE  # program-running git settings neutralised
# Fetch needs ssh for ssh remotes, so allow plain ssh (never a repo-configured command).
FETCH = [engine.GIT, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
         "-c", "core.sshCommand=ssh", "-c", "core.pager=cat"]
if not os.environ.get("REPOGUARD_TEST"):
    FETCH += ["-c", "protocol.file.allow=never"]  # a planted remote can't point at local files

VENDORED = re.compile(r"(?:^|/)(?:node_modules|vendor|site-packages|dist-packages|\.venv[^/]*|venv|Pods)/")
DROPPERS = re.compile(r"(?:^|/)(?:config\.bat|temp_auto_push\.bat|temp_interactive_push\.bat)$")
MEDIA = re.compile(r"\.(?:png|jpe?g|gif|webp|ico|woff2?|ttf|otf|eot|mp3|mp4|pdf|svg)$", re.I)
GITIGNORE_MARKERS = re.compile(r"^(?:config\.bat|temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json)\s*$")
SHIM_LINES = {"var module = { exports: {} };", "var module = {exports: {}};", "var module={exports:{}};"}
OFFSCREEN = re.compile(r"(\S)([ \t]{100,})(\S.*)$")
ETH = re.compile(r"ethplorer\.io|eth_getTransactionByHash|0x3b1574417524c11a7403c4b232CAcBb320CceBC6")


def find_node():
    for p in ([shutil.which("node") or ""] + [os.path.join(os.environ.get(v, ""), "nodejs", "node.exe")
                                              for v in ("ProgramFiles", "ProgramFiles(x86)")]):
        if os.access(p, os.X_OK):
            return p
    return shutil.which("node")


NODE = find_node()


# ---------------------------------------------------------------- text surgery

class Manual(Exception):
    """The file can't be cleaned automatically; leave it and report why."""


def strip_offscreen(text, notes):
    out = []
    for line in text.split("\n"):
        m = OFFSCREEN.search(line)
        if m and len(m.group(2)) >= 100:
            keep = line[:m.start(2)].rstrip()
            out.append(keep)
            notes.append("cut code hidden off-screen")
        else:
            out.append(line)
    return "\n".join(out)


def strip_shims(text, notes):
    out, seen_imports = [], set()
    has_const = "const require = createRequire" in text
    for line in text.split("\n"):
        s = line.strip()
        if s in SHIM_LINES:
            notes.append("removed loader line"); continue
        if s == "var require = createRequire(import.meta.url);" and has_const:
            notes.append("removed loader line"); continue
        if s.startswith("import ") and s in seen_imports:
            notes.append("removed duplicate import"); continue
        if s.startswith("import "):
            seen_imports.add(s)
        out.append(line)
    return "\n".join(out)


def strip_python_loader(text, notes):
    """Remove the try: block that pulls code from an Ethereum transaction."""
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        if lines[i].strip() == "try:":
            indent = len(lines[i]) - len(lines[i].lstrip())
            j = i + 1
            while j < len(lines):
                ln = lines[j]
                if ln.strip() == "":
                    j += 1; continue
                ind = len(ln) - len(ln.lstrip())
                if ind > indent or (ind == indent and re.match(r"(except\b|finally\s*:|else\s*:)", ln.strip())):
                    j += 1; continue
                break
            block = "\n".join(lines[i:j])
            if ETH.search(block):
                start = i
                # the payload defines DEFAULT_TIMEOUT just above the try: and nothing else uses it
                k = i - 1
                while k >= 0 and lines[k].strip() == "":
                    k -= 1
                rest = "\n".join(lines[:k] + lines[j:])
                if k >= 0 and lines[k].strip().startswith("DEFAULT_TIMEOUT") and "DEFAULT_TIMEOUT" not in rest:
                    start = k
                del lines[start:j]
                notes.append("removed blockchain loader block")
                continue
        i += 1
    return "\n".join(lines)


def clean_tasks_json(text, notes):
    loose = re.sub(r"(?m)^\s*//.*$", "", text)
    loose = re.sub(r",(\s*[}\]])", r"\1", loose)
    try:
        data = json.loads(loose)
    except ValueError:
        raise Manual("tasks.json is not readable JSON")
    tasks = data.get("tasks", []) if isinstance(data, dict) else []
    keep = [t for t in tasks if not (isinstance(t, dict) and (t.get("runOptions") or {}).get("runOn") == "folderOpen")]
    if len(keep) == len(tasks):
        return text
    notes.append(f"removed {len(tasks) - len(keep)} auto-run task(s)")
    data["tasks"] = keep
    meaningful = {k: v for k, v in data.items() if k not in ("version",) and v not in ([], {}, None)}
    # the worm's file also carries a fake "configurations" block
    if not keep and set(meaningful) <= {"configurations"}:
        return None
    return json.dumps(data, indent=2) + "\n"


def _auto_runs(v):
    return '"folderOpen"' in json.dumps(v)


def clean_settings_json(text, notes):
    """Drop the worm's keys from VS Code settings: automatic tasks on, an embedded folderOpen task,
    and the hidden terminal that keeps the payload out of sight. Other settings are kept."""
    loose = re.sub(r"(?m)^\s*//.*$", "", text)
    loose = re.sub(r",(\s*[}\]])", r"\1", loose)
    try:
        data = json.loads(loose)
    except ValueError:
        data = None
    if isinstance(data, dict):
        drop = [k for k in data if k == "task.allowAutomaticTasks"
                or (k == "tasks" and _auto_runs(data[k]))
                or (k == "terminal.integrated.hideOnStartup" and data[k] in ("always", "whenEmpty"))]
        if not drop:
            return text
        notes.append("removed " + ", ".join(drop))
        for k in drop:
            del data[k]
        if not data:
            return None
        return json.dumps(data, indent=2) + "\n"
    # not parseable: line-level fallback
    kept = [l for l in text.split("\n") if not re.search(r'"task\.allowAutomaticTasks"\s*:|"terminal\.integrated\.hideOnStartup"\s*:', l)]
    if len(kept) != len(text.split("\n")):
        notes.append("turned off automatic tasks")
    text = "\n".join(kept)
    if re.sub(r"[\s{},]", "", text) == "":
        return None
    return text


def clean_text(path, data, hits):
    """Return (new bytes | None for delete, notes). Raises Manual when it can't be done safely."""
    base = os.path.basename(path)
    notes = []
    rules = {h[0] for h in hits}
    if path.endswith(".orc") or DROPPERS.search(path):
        return None, ["whole file is the malware payload"]
    if "fake_media" in rules or (MEDIA.search(path) and "fake_media" in rules):
        return None, ["code disguised as a media/font file"]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Manual("not a text file")
    crlf = "\r\n" in text
    text = text.replace("\r\n", "\n")
    orig = text

    if base == "init":
        return None, ["loader file named init"]
    if base == ".gitignore":
        kept = [l for l in text.split("\n") if not GITIGNORE_MARKERS.match(l.strip())]
        if len(kept) != len(text.split("\n")):
            notes.append("removed worm marker lines")
        text = "\n".join(kept)
    elif path.endswith(".vscode/tasks.json"):
        new = clean_tasks_json(text, notes)
        if new is None:
            return None, notes + ["nothing else left in tasks.json"]
        text = new
    elif path.endswith(".vscode/settings.json"):
        new = clean_settings_json(text, notes)
        if new is None:
            return None, notes + ["nothing else left in settings.json"]
        text = new
    else:
        if base == "package.json":
            new = re.sub(r"node\s+(?:\./)?init\s*(?:&&|;)\s*", "", text)
            if new != text:
                notes.append("removed `node init` from scripts")
            text = new
        if ETH.search(text):
            text = strip_python_loader(text, notes)
            if not text.strip():
                return None, notes + ["file held only the loader"]
        text = strip_offscreen(text, notes)
        text = strip_shims(text, notes)

    if text == orig:
        raise Manual("nothing recognisable to cut; check it by hand")
    new = text.replace("\n", "\r\n") if crlf else text
    out = new.encode("utf-8")
    left = [h for h in RULES.check(path, out) if h[1] == "block"]
    if left:
        raise Manual("still matches: " + ", ".join(sorted({h[2] for h in left})))
    syntax_check(path, new, orig)
    return out, notes


def syntax_check(path, text, orig=None):
    base = os.path.basename(path)
    if base.endswith(".json") and not path.endswith((".vscode/settings.json", ".vscode/tasks.json", "tsconfig.json", "jsconfig.json")):
        try:
            json.loads(text)
        except ValueError as e:
            raise Manual(f"cleaned file is not valid JSON ({e})")
    elif base.endswith(".py"):
        try:
            compile(text, path, "exec", dont_inherit=True)
        except SyntaxError as e:
            raise Manual(f"cleaned Python would not compile ({e.msg})")
    elif re.search(r"\.(?:js|mjs|cjs)$", base) and NODE:
        ext = os.path.splitext(base)[1]
        fd, tmp = tempfile.mkstemp(suffix=ext, dir=TMPDIR)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        r = subprocess.run([NODE, "--check", tmp], capture_output=True, text=True, cwd=os.path.expanduser("~"), creationflags=engine.NO_WINDOW)  # parse only, never runs
        os.unlink(tmp)
        if r.returncode != 0:
            # If node can't parse the original either (an old node, or syntax it doesn't know), its
            # verdict says nothing about the cleaning. The rules re-check already passed.
            if orig is not None:
                fd, tmp = tempfile.mkstemp(suffix=ext, dir=TMPDIR)
                with os.fdopen(fd, "w") as fh:
                    fh.write(orig)
                r0 = subprocess.run([NODE, "--check", tmp], capture_output=True, text=True, cwd=os.path.expanduser("~"), creationflags=engine.NO_WINDOW)
                os.unlink(tmp)
                if r0.returncode != 0:
                    return
            err = next((l.strip() for l in r.stderr.splitlines() if "Error" in l), r.stderr.strip()[:120])
            raise Manual(f"cleaned JavaScript would not parse ({err[:140]})")


# ---------------------------------------------------------------- preview

def _show(line, limit=240):
    """One line made readable: control characters replaced, long blank runs named, long lines cut."""
    line = "".join(c if c >= " " or c == "\t" else "\ufffd" for c in line)
    line = re.sub(r"[ \t]{20,}", lambda m: f"\u27e8{len(m.group(0))} blank characters\u27e9", line)
    return line if len(line) <= limit else line[:limit] + f" \u2026 (+{len(line) - limit:,} more characters)"


def describe(path, old, new, notes, max_lines=14):
    """What cleaning does to one file, shown to the person before anything changes."""
    text = old.decode("utf-8", "replace").replace("\r\n", "\n")
    ol = text.split("\n")
    if new is None:
        removed, kept, cut = [l for l in ol], [], len(text)
        while removed and not removed[-1].strip():
            removed.pop()
    else:
        ntext = new.decode("utf-8", "replace").replace("\r\n", "\n")
        nl = ntext.split("\n")
        removed, kept = [], []
        sm = difflib.SequenceMatcher(None, ol, nl, autojunk=len(ol) > 5000)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag != "equal":
                removed += ol[i1:i2]
                kept += nl[j1:j2]
        cut = max(0, len(text) - len(ntext))
    return {"path": path, "action": "delete" if new is None else "clean", "notes": list(dict.fromkeys(notes)),
            "removed": [_show(l) for l in removed[:max_lines]], "more_removed": max(0, len(removed) - max_lines),
            "kept": [_show(l) for l in kept[:max_lines]], "more_kept": max(0, len(kept) - max_lines),
            "removed_chars": cut}


def plan_item(repo, path, data, hits, where):
    """describe() for one infected file version, or why it needs a person."""
    try:
        new, notes = clean_text(path, data, hits)
        item = describe(path, data, new, notes)
    except Manual as e:
        item = {"path": path, "action": "manual", "why": str(e), "notes": [], "removed": [], "kept": [],
                "more_removed": 0, "more_kept": 0, "removed_chars": 0}
    item.update(repo=repo, where=[where], found=sorted({h[2] for h in hits}))
    return item


def fingerprint(findings):
    """Ties an approval to the threats that were shown; the real run refuses if they changed."""
    return hashlib.sha256("\n".join(sorted(findings)).encode()).hexdigest()[:16]


def ref_label(ref):
    if ref.startswith("refs/remotes/"):
        return "GitHub copy " + ref[len("refs/remotes/"):]
    if ref.startswith("refs/heads/"):
        return "branch " + ref[len("refs/heads/"):]
    return "tag " + ref[len("refs/tags/"):]


def build_plan(disk, repos, report):
    """Everything Remove Malware would do, worked out without changing anything (no fetch either)."""
    items, refs = {}, []

    def add(repo, path, data, hits, where):
        key = (repo, path, hashlib.sha1(data).hexdigest())
        if key in items:
            if where not in items[key]["where"]:
                items[key]["where"].append(where)
        else:
            items[key] = plan_item(repo, path, data, hits, where)

    for repo in sorted(repos):
        if not os.path.isdir(os.path.join(repo, ".git")):
            continue
        current = head_branch(repo)
        for ref in all_refs(repo):
            sha = rev(repo, ref)
            hits = tree_hits(repo, sha) if sha else None
            if not hits:
                continue
            for p, h in hits.items():
                data = blob_at(repo, sha, p)
                if data is not None:
                    add(repo, p, data, h, ref_label(ref))
            r = {"repo": repo, "ref": ref_label(ref), "files": sorted(hits)}
            if ref.startswith("refs/remotes/"):
                r["kind"] = "github"
            elif ref.startswith("refs/heads/"):
                r["kind"] = "branch"
                r["checked_out"] = current == ref
                up = rev(repo, "refs/remotes/origin/" + ref[len("refs/heads/"):])
                r["plan"] = ("move" if up and not tree_hits(repo, up) and only_malware_differs(repo, sha, up, hits)
                             else "commit")
            else:
                r["kind"] = "tag"
            refs.append(r)
    for (root, rel), hits in sorted(disk.items()):
        if VENDORED.search("/" + rel):
            report["skipped"].append({"path": f"{root}/{rel}", "why": "inside a library folder; most likely a false alarm"})
            continue
        try:
            data = open(os.path.join(root, rel), "rb").read()
        except OSError:
            continue
        h = [x for x in RULES.check(rel, data) if x[1] == "block"]
        if h:
            add(root, rel, data, h, "files on disk")
    return sorted(items.values(), key=lambda i: (i["repo"], i["path"])), refs


# ---------------------------------------------------------------- backups

def backup(src_path, data, label):
    drive, rest = os.path.splitdrive(src_path)  # C:\\x\\y -> C\\x\\y, so it stays inside the backup folder
    rel = (drive.replace(":", "") + rest).lstrip("/\\")
    dst = os.path.join(BACKUP, rel + (f"@{label}" if label else "") + ".quarantined")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as fh:
        fh.write(data)
    os.chmod(dst, 0o400)
    return dst


# ---------------------------------------------------------------- files on disk

def clean_disk_file(root, rel, hits, report):
    path = os.path.join(root, rel)
    tag = f"{root}/{rel}"
    if VENDORED.search("/" + rel):
        report["skipped"].append({"path": tag, "why": "inside a library folder; most likely a false alarm"})
        return
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return
        data = open(path, "rb").read()
    except OSError:
        return  # already gone
    hits = [h for h in RULES.check(rel, data) if h[1] == "block"]
    if not hits:
        return  # already clean (fixed when its branch moved)
    try:
        new, notes = clean_text(rel, data, hits)
    except Manual as e:
        report["manual"].append({"path": tag, "why": str(e)})
        return
    saved = backup(path, data, "")
    if new is None:
        os.unlink(path)
        report["files"].append({"path": tag, "action": "deleted", "notes": notes, "backup": saved})
    else:
        tmp = path + ".rg-tmp"
        with open(tmp, "wb") as fh:
            fh.write(new)
        os.chmod(tmp, stat.S_IMODE(st.st_mode))
        os.replace(tmp, path)
        report["files"].append({"path": tag, "action": "cleaned", "notes": notes, "backup": saved})


# ---------------------------------------------------------------- git

def git(repo, *args, env=None, base=SAFE, timeout=300):
    p = subprocess.run(base + ["-C", repo, *args], capture_output=True, env=env or GIT_ENV, cwd=os.path.expanduser("~"), creationflags=engine.NO_WINDOW, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def rev(repo, ref):
    rc, out, _ = git(repo, "rev-parse", "--verify", "--quiet", ref + "^{commit}")
    return out.decode().strip() if rc == 0 else None


_TREE_CACHE = {}


def all_refs(repo):
    rc, out, _ = git(repo, "for-each-ref", "--format=%(refname) %(objecttype)")
    refs = []
    for line in out.decode("utf8", "replace").splitlines():
        ref, typ = line.rsplit(" ", 1)
        if ref.endswith("/HEAD") or ref.startswith(("refs/pull/", "refs/stash", "refs/notes/")):
            continue
        if typ in ("commit", "tag"):
            refs.append(ref)
    return refs


def tree_hits(repo, sha):
    """{path: [(rule, sev, label)]} for blocking hits in a commit's tree."""
    rc, out, _ = git(repo, "rev-parse", sha + "^{tree}")
    tree = out.decode().strip()
    key = (repo, tree)
    if key not in _TREE_CACHE:
        _TREE_CACHE[key] = _tree_hits(repo, tree)
    return _TREE_CACHE[key]


def _tree_hits(repo, sha):
    rc, out, _ = git(repo, "ls-tree", "-r", "-z", sha)
    if rc:
        return None
    items = {}
    for row in out.split(b"\0"):
        if not row:
            continue
        meta, p = row.split(b"\t", 1)
        f = meta.split()
        if f[1] == b"blob":
            items.setdefault(f[2].decode(), []).append(p.decode("utf8", "replace"))
    hits = {}
    for blob, data in engine.read_blobs(repo, list(items), RULES.max):
        for p in items[blob]:
            if VENDORED.search("/" + p):
                continue
            h = [x for x in RULES.check(p, data) if x[1] == "block"]
            if h:
                hits[p] = h
    return hits


def blob_at(repo, sha, path):
    rc, out, _ = git(repo, "cat-file", "blob", f"{sha}:{path}")
    return out if rc == 0 else None


def head_branch(repo):
    try:
        head = open(os.path.join(repo, ".git", "HEAD")).read().strip()
    except OSError:
        return None
    return head[len("ref: "):] if head.startswith("ref: ") else None


def worktree_dirty(repo):
    rc, out, _ = git(repo, "status", "--porcelain", "--untracked-files=no")
    return rc != 0 or bool(out.strip())


def move_branch(repo, ref, new_sha, report, why):
    old = rev(repo, ref)
    if head_branch(repo) == ref:
        # checked out: update the working files too; --keep refuses to clobber local edits
        rc, _, err = git(repo, "reset", "--keep", new_sha)
        if rc:
            report["manual"].append({"path": f"{repo} {ref}", "why": "branch is checked out and has local edits in the same files; commit or stash them, then run Remove Malware again"})
            return False
    else:
        rc, _, err = git(repo, "update-ref", "-m", "RepoGuard: remove malware", ref, new_sha, old)
        if rc:
            report["manual"].append({"path": f"{repo} {ref}", "why": err.decode()[:200]})
            return False
    report["refs"].append({"repo": repo, "ref": ref, "action": why, "from": old[:7], "to": new_sha[:7]})
    return True


def cleanup_commit(repo, ref, sha, hits, report):
    """New commit on top of sha with each infected file cleaned. Keeps all work."""
    fd, index = tempfile.mkstemp(dir=TMPDIR)
    os.close(fd)
    env = dict(GIT_ENV, GIT_INDEX_FILE=index)
    try:
        git(repo, "read-tree", sha, env=env)
        changed = 0
        for p, h in hits.items():
            data = blob_at(repo, sha, p)
            if data is None:
                continue
            try:
                new, notes = clean_text(p, data, h)
            except Manual as e:
                report["manual"].append({"path": f"{repo} {ref}:{p}", "why": str(e)})
                return None
            if new is None:
                git(repo, "update-index", "--force-remove", "--", p, env=env)
            else:
                proc = subprocess.run(SAFE + ["-C", repo, "hash-object", "-w", "--stdin"], input=new,
                                      capture_output=True, env=GIT_ENV, cwd=os.path.expanduser("~"), creationflags=engine.NO_WINDOW)
                blob = proc.stdout.decode().strip()
                rc, out, _ = git(repo, "ls-tree", sha, "--", p)
                mode = out.split()[0].decode() if out else "100644"
                git(repo, "update-index", "--cacheinfo", f"{mode},{blob},{p}", env=env)
            changed += 1
        if not changed:
            return None
        rc, out, _ = git(repo, "write-tree", env=env)
        tree = out.decode().strip()
        cenv = dict(GIT_ENV, GIT_AUTHOR_NAME="RepoGuard", GIT_AUTHOR_EMAIL="repoguard@localhost",
                    GIT_COMMITTER_NAME="RepoGuard", GIT_COMMITTER_EMAIL="repoguard@localhost")
        p = subprocess.run(SAFE + ["-C", repo, "commit-tree", tree, "-p", sha, "-m", "Remove malware (RepoGuard)"],
                           capture_output=True, env=cenv, cwd=os.path.expanduser("~"), creationflags=engine.NO_WINDOW)
        return p.stdout.decode().strip() or None
    finally:
        try:
            os.unlink(index)
        except OSError:
            pass


def only_malware_differs(repo, local, upstream, local_hits):
    """True when every file that differs between local and upstream is malware or its cleaned form."""
    rc, out, _ = git(repo, "diff", "--no-renames", "--name-only", "-z", upstream, local)
    if rc:
        return False
    for p in [x.decode("utf8", "replace") for x in out.split(b"\0") if x]:
        if p not in local_hits:
            return False
        ldata = blob_at(repo, local, p)
        udata = blob_at(repo, upstream, p)
        try:
            new, _ = clean_text(p, ldata, local_hits[p])
        except Manual:
            return False
        norm = lambda b: None if b is None else b.replace(b"\r\n", b"\n").rstrip()
        if udata is None and new is not None and norm(new) in (b"", b"{}", b"{\n}"):
            new = None  # a worm-added file that cleans down to nothing
        if norm(new) != norm(udata):
            return False
    return True


def push_fix(repo, ref, sha, hits, report):
    """Fix an infected GitHub branch with a normal (fast-forward) push of a cleanup commit.
    No force-push: the branch history stays as it is, the malware is removed on top."""
    parts = ref.split("/")  # refs/remotes/<remote>/<branch...>
    remote, name = parts[2], "/".join(parts[3:])
    new = cleanup_commit(repo, ref, sha, hits, report)
    if not new:
        return False
    rc, _, err = git(repo, "push", "--quiet", "--no-verify", remote, f"{new}:refs/heads/{name}", base=FETCH, timeout=180,
                     env=dict(GIT_ENV, GIT_TERMINAL_PROMPT="0"))
    if rc:
        msg = err.decode("utf8", "replace").strip()
        if "protected branch" in msg or "GH006" in msg:
            why = "GitHub branch is protected; open a pull request or allow pushes, then try again"
        elif "rejected" in msg:
            why = "GitHub branch changed while cleaning; run Remove Malware again"
        else:
            why = "push to GitHub failed: " + msg[-200:]
        report["manual"].append({"path": f"{repo} {remote}/{name}", "why": why})
        return False
    git(repo, "update-ref", "-m", "RepoGuard: fixed on GitHub", ref, new, sha)
    report["refs"].append({"repo": repo, "ref": ref, "action": f"fixed on GitHub with a malware-removal commit (pushed, no force)",
                           "from": sha[:7], "to": new[:7]})
    report["pushed"].append({"repo": repo, "remote": remote, "branch": name, "commit": new})
    return True


def clean_repo_refs(repo, report, permanent, fix_github=False):
    # The scan engine stores one finding per file version, so a file infected on several
    # branches shows up once. Check every branch and tag here instead of trusting that list.
    fetched = set()
    if fix_github:
        # bring back copies of GitHub branches that an earlier run dropped, so they can be fixed
        rc, out, _ = git(repo, "remote")
        for remote in out.decode().split():
            rc, _, err = git(repo, "fetch", "--prune", "--no-tags", "--quiet", remote, base=FETCH, timeout=180,
                             env=dict(GIT_ENV, GIT_TERMINAL_PROMPT="0"))
            report["fetched"].append({"repo": repo, "remote": remote, "ok": rc == 0,
                                      "error": "" if rc == 0 else err.decode("utf8", "replace").strip()[:200]})
            fetched.add(remote)
    refs = []
    for ref in all_refs(repo):
        sha = rev(repo, ref)
        if sha and tree_hits(repo, sha):
            refs.append(ref)
    if not refs:
        return
    remotes = sorted({r.split("/")[2] for r in refs if r.startswith("refs/remotes/")})
    for remote in [r for r in remotes if r not in fetched]:
        rc, _, err = git(repo, "fetch", "--prune", "--no-tags", "--quiet", remote, base=FETCH, timeout=180,
                         env=dict(GIT_ENV, GIT_TERMINAL_PROMPT="0"))
        report["fetched"].append({"repo": repo, "remote": remote, "ok": rc == 0,
                                  "error": "" if rc == 0 else err.decode("utf8", "replace").strip()[:200]})
    moved_any = False
    # GitHub copies first, so local branches can then follow a branch fixed on GitHub
    order = {"refs/remotes/": 0, "refs/heads/": 1, "refs/tags/": 2}
    for ref in sorted(refs, key=lambda r: (next((v for k, v in order.items() if r.startswith(k)), 3), r)):
        sha = rev(repo, ref)
        if sha is None:
            report["refs"].append({"repo": repo, "ref": ref, "action": "gone after re-fetch (pruned on GitHub)"})
            continue
        hits = tree_hits(repo, sha)
        if hits is None:
            continue
        if not hits:
            report["refs"].append({"repo": repo, "ref": ref, "action": "clean after re-fetch from GitHub"})
            continue
        if ref.startswith("refs/remotes/"):
            if fix_github and push_fix(repo, ref, sha, hits, report):
                continue
            # only a cached copy of a remote branch; GitHub still has it infected
            git(repo, "update-ref", "-d", ref, sha)
            report["refs"].append({"repo": repo, "ref": ref, "action": "dropped infected cached copy (re-fetch didn't clean it)"})
            moved_any = True
        elif ref.startswith("refs/heads/"):
            name = ref[len("refs/heads/"):]
            upstream = None
            for cand in (f"refs/remotes/origin/{name}",):
                u = rev(repo, cand)
                if u and not tree_hits(repo, u):
                    upstream = u
            if upstream and only_malware_differs(repo, sha, upstream, hits):
                moved_any |= move_branch(repo, ref, upstream, report, "moved to the clean GitHub version")
            else:
                new = cleanup_commit(repo, ref, sha, hits, report)
                if new:
                    moved_any |= move_branch(repo, ref, new, report, "added a malware-removal commit (kept your work)")
        elif ref.startswith("refs/tags/"):
            if permanent:
                rc, _, _ = git(repo, "tag", "-d", ref[len("refs/tags/"):])
                if rc == 0:
                    report["refs"].append({"repo": repo, "ref": ref, "action": "deleted infected tag"})
                    moved_any = True
            else:
                report["kept_tags"].append({"repo": repo, "ref": ref})
    if permanent and moved_any:
        git(repo, "reflog", "expire", "--expire-unreachable=now", "--all", timeout=600)
        rc, _, _ = git(repo, "gc", "--prune=now", "--quiet", timeout=1800)
        report["purged"].append({"repo": repo, "ok": rc == 0})


# ---------------------------------------------------------------- main

def main():
    global RULES, BACKUP, TMPDIR
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--backup", default="")
    ap.add_argument("--log", default="")
    ap.add_argument("--permanent", action="store_true")
    ap.add_argument("--fix-github", action="store_true", help="also fix infected GitHub branches with a pushed cleanup commit")
    ap.add_argument("--preview", action="store_true", help="print every planned change as JSON; change nothing")
    ap.add_argument("--expect", default="", help="fingerprint from --preview; refuse to run if the threats changed")
    a = ap.parse_args()
    if not a.preview and not a.backup:
        ap.error("--backup is required")
    RULES = engine.Rules(a.rules)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    BACKUP = os.path.join(a.backup, stamp)
    TMPDIR = os.path.join(a.backup, ".tmp") if a.backup else tempfile.mkdtemp(prefix="rg-preview-")
    os.makedirs(TMPDIR, exist_ok=True)
    report = {"files": [], "refs": [], "fetched": [], "manual": [], "skipped": [], "kept_tags": [], "purged": [], "pushed": [],
              "backup": BACKUP, "permanent": a.permanent}

    saved = json.load(open(a.state)).get("findings", {})
    findings = list(saved.values())
    fp = fingerprint(saved)
    if a.expect and a.expect != fp:
        shutil.rmtree(TMPDIR, ignore_errors=True)
        print(json.dumps({"error": "changed", "fingerprint": fp}))
        sys.exit(3)
    disk, repos = {}, set()
    for f in findings:
        w = f["where"]
        if w == "folder":
            disk.setdefault((f["root"], f["path"]), []).append((f["rule"], "block", f["label"]))
        if w != "git-config":
            repos.add(f["root"])
        # git-config findings are left for a person to look at
        elif w == "git-config":
            report["manual"].append({"path": f"{f['root']}/{f['path']}", "why": "git setting that can run a program; check it by hand"})

    if a.preview:
        items, refs = build_plan(disk, repos, report)
        shutil.rmtree(TMPDIR, ignore_errors=True)
        print(json.dumps({"fingerprint": fp, "items": items, "refs": refs, "manual": report["manual"],
                          "skipped": report["skipped"]}))
        return

    # Branches first: moving a checked-out branch to its clean version also fixes its files.
    for repo in sorted(repos):
        if os.path.isdir(os.path.join(repo, ".git")):
            try:
                clean_repo_refs(repo, report, a.permanent, a.fix_github)
            except subprocess.TimeoutExpired:
                report["manual"].append({"path": repo, "why": "git took too long; try again"})
    for (root, rel), hits in sorted(disk.items()):
        clean_disk_file(root, rel, hits, report)

    shutil.rmtree(TMPDIR, ignore_errors=True)
    if a.log:
        with open(a.log, "a") as fh:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for x in report["files"]:
                fh.write(f"{now} CLEANED {x['path']}: {x['action']} ({'; '.join(x['notes'])})\n")
            for x in report["refs"]:
                fh.write(f"{now} CLEANED {x['repo']} {x['ref']}: {x['action']}\n")
            for x in report["manual"]:
                fh.write(f"{now} MANUAL {x['path']}: {x['why']}\n")
    json.dump(report, open(os.path.join(a.backup, "last-clean.json"), "w"), indent=1)
    print(json.dumps({"files": len(report["files"]), "refs": len(report["refs"]), "manual": len(report["manual"]),
                      "skipped": len(report["skipped"]), "kept_tags": len(report["kept_tags"]),
                      "fetch_failed": sum(1 for x in report["fetched"] if not x["ok"]),
                      "purged": len(report["purged"]), "pushed": len(report["pushed"]), "backup": BACKUP,
                      "manual_items": [f"{x['path'].replace(os.path.expanduser('~') + '/', '')}: {x['why']}" for x in report["manual"][:8]]}))


if __name__ == "__main__":
    main()
