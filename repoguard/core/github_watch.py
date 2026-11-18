"""RepoGuard GitHub watch: notices new pushes to your GitHub repos and scans only what changed.

  github_watch.py poll --rules R --state S --log L [--fix] [--fix-existing]

Every repo you can push to is checked with a conditional request, so a repo with no new pushes
costs nothing against GitHub's rate limit. For a branch that moved, the files changed since the
last known commit are read through the API and checked with the same rules as the Mac scanner.

With --fix, malware found in a new push is removed straight away: RepoGuard makes one commit on
top of the branch through GitHub's API, with each infected file cleaned or deleted, and moves the
branch to it without force. If the branch moved again meanwhile, it tries on the next poll.
Branches that were already infected when the watch started are only reported; --fix-existing
fixes those too (the "Fix all on GitHub" button).

Uses your GitHub CLI login (gh auth token). Prints a JSON summary.
"""
import argparse, base64, datetime, importlib.util, json, os, re, subprocess, sys, time, urllib.error, urllib.parse, urllib.request, shutil

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location("rgw_" + name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


engine = _load("engine")
cleaner = _load("cleaner")

API = os.environ.get("REPOGUARD_GITHUB_API", "https://api.github.com")
REPO_LIST_EVERY = 6 * 3600
# On a branch seen for the first time, these are the files the worm uses; read them by name.
HOT = re.compile(r"(?:^|/)(?:\.gitignore|package\.json|init|conftest\.py|session\.py|\.vscode/[^/]+\.json"
                 r"|[^/]*\.config\.(?:js|cjs|mjs|ts)|\.babelrc(?:\.js)?|ecosystem\.config\.js"
                 r"|[^/]*\.orc|(?:public|assets|static)/fonts/[^/]+|config\.bat|temp_[a-z_]+\.bat)$")


# RepoGuard's own repo: its detection code and tests spell out the malware's names, addresses and
# loader lines on purpose, so those files would always match the rules that look for that text.
# Only those exact files and only those rules are skipped. Hidden off-screen code and obfuscation
# are still caught in them, and every other file in the repo (a planted utils/session.py, say)
# is checked normally.
SELF_REPO = re.compile(r"(?:^|/)repo-?guard(?:-windows)?$", re.I)
SELF_FILES = re.compile(r"^(?:Resources/(?:engine|cleaner|server_agent|mac_agent|github_watch|storage)\.py"
                        r"|Resources/rules\.json|tests/[^/]+\.(?:sh|py)"
                        r"|repoguard/core/(?:engine|cleaner|github_watch|pc_agent|gitscan)\.py|repoguard/core/rules\.json)$")
SIGNATURE_RULES = {"known_code", "known_host", "loader_lines", "eth_loader", "autorun", "encoded_exec",
                   "npm_loader", "gitignore_marker"}


def exempt(repo, path, rule):
    return bool(SELF_REPO.search(repo) and SELF_FILES.match(path) and rule in SIGNATURE_RULES)


class GitHubError(Exception):
    def __init__(self, status, msg):
        super().__init__(f"GitHub {status}: {msg}")
        self.status = status


class GitHub:
    def __init__(self, token):
        self.token = token
        self.remaining = None
        self.calls = 0

    def request(self, method, path, body=None, etag=None):
        url = path if path.startswith("http") else API + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self.token)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "RepoGuard")
        if etag:
            req.add_header("If-None-Match", etag)
        self.calls += 1
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                self.remaining = r.headers.get("X-RateLimit-Remaining", self.remaining)
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None), r.headers
        except urllib.error.HTTPError as e:
            self.remaining = e.headers.get("X-RateLimit-Remaining", self.remaining)
            if e.code == 304:
                return 304, None, e.headers
            try:
                msg = json.loads(e.read()).get("message", "")
            except Exception:
                msg = e.reason
            raise GitHubError(e.code, msg)
        except (urllib.error.URLError, OSError, ValueError) as e:  # network trouble: skip, try next time
            raise GitHubError(0, f"network error: {e}")

    def pages(self, path, etag=None):
        """GET every page. Returns (304, None, etag) when the first page is unchanged."""
        status, data, headers = self.request("GET", path, etag=etag)
        if status == 304:
            return 304, None, etag
        new_etag = headers.get("ETag")
        items = list(data or [])
        link = headers.get("Link") or ""
        while 'rel="next"' in link:
            nxt = re.search(r'<([^>]+)>;\s*rel="next"', link).group(1)
            _, data, headers = self.request("GET", nxt)
            items += data or []
            link = headers.get("Link") or ""
        return 200, items, new_etag


def gh_token():
    if os.environ.get("REPOGUARD_GITHUB_TOKEN"):
        return os.environ["REPOGUARD_GITHUB_TOKEN"]
    for gh in (shutil.which("gh") or "", os.path.join(os.environ.get("ProgramFiles", ""), "GitHub CLI", "gh.exe")):
        if gh and os.path.exists(gh):
            p = subprocess.run([gh, "auth", "token"], capture_output=True, cwd=os.path.expanduser("~"), timeout=30,
                               creationflags=engine.NO_WINDOW)
            if p.returncode == 0 and p.stdout.strip():
                return p.stdout.decode().strip()
            raise SystemExit(json.dumps({"error": "Not signed in to the GitHub CLI. Run: gh auth login"}))
    raise SystemExit(json.dumps({"error": "The GitHub CLI isn't installed. Install it with: winget install GitHub.cli, then run gh auth login"}))


# ---------------------------------------------------------------- scanning

class Scanner:
    def __init__(self, gh, rules, state):
        self.gh, self.rules = gh, rules
        self.verdicts = state.setdefault("blob_verdicts", {})  # blob sha -> [[rule, sev, label], ...]

    def wants_content(self, path):
        base = os.path.basename(path)
        return bool(self.rules.code.search(path) or self.rules.media.search(path) or HOT.search(path)
                    or base in (".gitignore", "package.json"))

    def blob(self, repo, sha):
        _, data, _ = self.gh.request("GET", f"/repos/{repo}/git/blobs/{sha}")
        return base64.b64decode(data["content"]) if data.get("encoding") == "base64" else data["content"].encode()

    def check(self, repo, path, sha, size):
        return [h for h in self._check(repo, path, sha, size) if not exempt(repo, path, h[0])]

    def _check(self, repo, path, sha, size):
        if self.rules.vendored.search(path):
            return []
        key = f"{sha}|{path}"  # some rules depend on the name, so cache per name too
        if key in self.verdicts:
            return [tuple(x) for x in self.verdicts[key]]
        data = None
        if self.wants_content(path) and (size is None or size <= self.rules.max):
            try:
                data = self.blob(repo, sha)
            except GitHubError:
                data = None
        hits = [h for h in self.rules.check(path, data) if h[1] == "block"]
        self.verdicts[key] = [list(h) for h in hits]
        return hits

    def changed_files(self, repo, old, new):
        """[(path, blob sha, size)] changed between two commits, or None if it can't be worked out."""
        try:
            _, data, _ = self.gh.request("GET", f"/repos/{repo}/compare/{old}...{new}?per_page=300")
        except GitHubError:
            return None
        files = data.get("files") or []
        if len(files) >= 300:
            return None  # very large push: fall back to the worm's usual files
        return [(f["filename"], f["sha"], None) for f in files if f.get("status") != "removed" and f.get("sha")]

    def hot_files(self, repo, sha):
        _, data, _ = self.gh.request("GET", f"/repos/{repo}/git/trees/{sha}?recursive=1")
        out = []
        for e in data.get("tree", []):
            if e.get("type") != "blob":
                continue
            p = e["path"]
            if HOT.search(p) or any(r["rx"].search(p) for r in self.rules.path_rules):
                out.append((p, e["sha"], e.get("size")))
        return out

    def scan_tree_hits(self, repo, files):
        hits = {}
        for path, sha, size in files:
            h = self.check(repo, path, sha, size)
            if h:
                hits[path] = h
        return hits


# ---------------------------------------------------------------- fixing

def fix_branch(gh, repo, branch, head, hits):
    """One commit on top of head with each infected file cleaned or deleted; fast-forward the branch."""
    _, commit, _ = gh.request("GET", f"/repos/{repo}/git/commits/{head}")
    _, tree, _ = gh.request("GET", f"/repos/{repo}/git/trees/{commit['tree']['sha']}?recursive=1")
    entries = {e["path"]: e for e in tree.get("tree", [])}
    changes, notes, manual = [], [], []
    for path, h in hits.items():
        e = entries.get(path)
        if not e:
            continue
        _, blob, _ = gh.request("GET", f"/repos/{repo}/git/blobs/{e['sha']}")
        data = base64.b64decode(blob["content"])
        try:
            new, n = cleaner.clean_text(path, data, list(h))
        except cleaner.Manual as m:
            manual.append(f"{path}: {m}")
            continue
        if new is None:
            changes.append({"path": path, "mode": e["mode"], "type": "blob", "sha": None})
            notes.append(f"deleted {path}")
        else:
            _, b, _ = gh.request("POST", f"/repos/{repo}/git/blobs",
                                 {"content": base64.b64encode(new).decode(), "encoding": "base64"})
            changes.append({"path": path, "mode": e["mode"], "type": "blob", "sha": b["sha"]})
            notes.append(f"cleaned {path}")
    if not changes:
        return None, notes, manual
    _, t, _ = gh.request("POST", f"/repos/{repo}/git/trees", {"base_tree": commit["tree"]["sha"], "tree": changes})
    msg = "Remove malware (RepoGuard)\n\n" + "\n".join("- " + n for n in notes)
    _, c, _ = gh.request("POST", f"/repos/{repo}/git/commits", {"message": msg, "tree": t["sha"], "parents": [head]})
    ref = urllib.parse.quote(branch, safe="/")
    gh.request("PATCH", f"/repos/{repo}/git/refs/heads/{ref}", {"sha": c["sha"], "force": False})
    return c["sha"], notes, manual


def preview(gh, findings):
    """Every change Fix All on GitHub would make, for the person to approve. Reads only."""
    out = []
    for key, f in sorted(findings.items()):
        b = {"id": f"{key}|{f['sha']}", "repo": f["repo"], "branch": f["branch"], "items": [], "error": ""}
        try:
            _, commit, _ = gh.request("GET", f"/repos/{f['repo']}/git/commits/{f['sha']}")
            _, tree, _ = gh.request("GET", f"/repos/{f['repo']}/git/trees/{commit['tree']['sha']}?recursive=1")
            entries = {e["path"]: e for e in tree.get("tree", [])}
            for path, h in sorted(f.get("hits", {}).items()):
                e = entries.get(path)
                if not e:
                    continue
                _, blob, _ = gh.request("GET", f"/repos/{f['repo']}/git/blobs/{e['sha']}")
                data = base64.b64decode(blob["content"])
                b["items"].append(cleaner.plan_item(f["repo"], path, data, [tuple(x) for x in h], f"GitHub branch {f['branch']}"))
        except GitHubError as e:
            b["error"] = explain(e)
        out.append(b)
    return out


def explain(e):
    if isinstance(e, GitHubError):
        if e.status == 422 and "protected" in str(e).lower() or e.status == 403 and "protected" in str(e).lower():
            return "branch is protected on GitHub; fix it with a pull request"
        if e.status in (403, 404):
            return "no permission to change this branch"
        if e.status == 422:
            return "branch changed meanwhile; will try again next check"
    return str(e)[:200]


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["poll", "preview"])
    ap.add_argument("--rules", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--log", default="")
    ap.add_argument("--fix", action="store_true", help="remove malware found in new pushes right away")
    ap.add_argument("--fix-existing", action="store_true", help="also fix branches already reported (Fix All on GitHub)")
    ap.add_argument("--approved", default="", help="JSON file listing the branch ids the person approved in the preview")
    a = ap.parse_args()

    rules = engine.Rules(a.rules)
    cleaner.RULES = rules
    cleaner.TMPDIR = os.path.join(os.path.dirname(os.path.abspath(a.state)), ".gw-tmp")
    os.makedirs(cleaner.TMPDIR, exist_ok=True)
    cleaner.NODE = cleaner.find_node()

    try:
        state = json.load(open(a.state))
    except (OSError, ValueError):
        state = {}
    repos_state = state.setdefault("repos", {})
    findings = state.setdefault("findings", {})  # "repo|branch" -> {...}
    gh = GitHub(gh_token())
    if a.mode == "preview":
        print(json.dumps({"branches": preview(gh, findings)}))
        return
    approved = None
    if a.approved:
        approved = set(json.load(open(a.approved)))
    scanner = Scanner(gh, rules, state)
    now = time.time()
    out = {"repos": 0, "changed": [], "new_findings": [], "fixed": [], "manual": [], "errors": []}
    log_lines = []
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # the list of repos, refreshed every few hours
    if now - state.get("repo_list_time", 0) > REPO_LIST_EVERY or not state.get("repo_list"):
        try:
            if not state.get("login"):
                try:
                    _, me, _ = gh.request("GET", "/user")
                    state["login"] = (me or {}).get("login", "")
                except GitHubError:
                    pass
            me = (state.get("login") or "").lower()

            def watched(r):
                if r.get("archived") or not (r.get("permissions") or {}).get("push"):
                    return False
                # Someone else's fork: write access comes only from the original repo, and its owner
                # has to fix it. Watch the original instead.
                owner = ((r.get("owner") or {}).get("login") or "").lower()
                return not (r.get("fork") and owner != me)

            _, items, _ = gh.pages("/user/repos?per_page=100&affiliation=owner,collaborator,organization_member")
            state["repo_list"] = sorted(r["full_name"] for r in items if watched(r))
            state["repo_list_time"] = now
        except GitHubError as e:
            out["errors"].append(f"couldn't list repos: {e}")
    repo_list = state.get("repo_list", [])
    # Drop repos that are no longer watched (left, lost push access, someone else's fork) and their alerts.
    listed = set(repo_list)
    for name in [r for r in repos_state if r not in listed]:
        repos_state.pop(name)
    for key in [k for k, f in findings.items() if f["repo"] not in listed]:
        findings.pop(key)
    # Re-apply the exemptions to alerts saved before they existed (the branch may not move again).
    for key, f in list(findings.items()):
        hits = {p: [x for x in h if not exempt(f["repo"], p, x[0])] for p, h in f.get("hits", {}).items()}
        hits = {p: h for p, h in hits.items() if h}
        if not hits:
            findings.pop(key)
        elif hits != f.get("hits"):
            f["hits"], f["files"] = hits, sorted(hits)
            f["labels"] = sorted({x[2] for h in hits.values() for x in h})
    out["repos"] = len(repo_list)
    first_run = not state.get("baseline_done")

    def do_fix(repo, name, head, hits, old):
        rs, key = repos_state[repo], f"{repo}|{name}"
        try:
            new_sha, notes, manual = fix_branch(gh, repo, name, head, hits)
        except GitHubError as e:
            why = explain(e)
            out["manual"].append(f"{repo} {name}: {why}")
            log_lines.append(f"{stamp} GITHUB MANUAL {repo} {name}: {why}")
            if "changed meanwhile" in why:
                rs["branches"][name] = old or ""
                rs["etag"] = None  # look again next time
            return
        for m in manual:
            out["manual"].append(f"{repo} {name}: {m}")
            log_lines.append(f"{stamp} GITHUB MANUAL {repo} {name} {m}")
        if new_sha:
            rs["branches"][name] = new_sha
            if not manual:
                findings.pop(key, None)
            out["fixed"].append({"repo": repo, "branch": name, "commit": new_sha, "notes": notes})
            log_lines.append(f"{stamp} GITHUB FIXED {repo} {name}: {'; '.join(notes)} (commit {new_sha[:7]}, no force-push)")

    for repo in repo_list:
        rs = repos_state.setdefault(repo, {"branches": {}})
        try:
            status, items, etag = gh.pages(f"/repos/{repo}/branches?per_page=100", etag=rs.get("etag"))
        except GitHubError as e:
            if e.status in (404, 409):  # gone or empty repo
                continue
            out["errors"].append(f"{repo}: {e}")
            continue
        if status == 304:
            continue
        rs["etag"] = etag
        current = {b["name"]: b["commit"]["sha"] for b in items}
        known = rs["branches"]
        for name in list(known):
            if name not in current:
                known.pop(name)
                findings.pop(f"{repo}|{name}", None)
        for name, head in current.items():
            old = known.get(name)
            if old == head:
                continue
            existing = old is None and first_run  # infected before we started watching
            try:
                files = scanner.changed_files(repo, old, head) if old else None
                if files is None:
                    files = scanner.hot_files(repo, head)
                hits = scanner.scan_tree_hits(repo, files)
                if old and hits:
                    # a push touched these files; make sure nothing else on the branch is infected too
                    hits.update(scanner.scan_tree_hits(repo, scanner.hot_files(repo, head)))
            except GitHubError as e:
                out["errors"].append(f"{repo} {name}: {e}")
                continue
            known[name] = head
            if old:
                out["changed"].append(f"{repo}:{name}")
            key = f"{repo}|{name}"
            if not hits:
                findings.pop(key, None)
                continue
            labels = sorted({l for h in hits.values() for _, _, l in h})
            f = {"repo": repo, "branch": name, "sha": head, "files": sorted(hits), "labels": labels,
                 "time": stamp, "existing": existing, "hits": {p: [list(x) for x in h] for p, h in hits.items()}}
            is_new = key not in findings or findings[key].get("sha") != head
            findings[key] = f
            if is_new and not existing:
                out["new_findings"].append(f)
                log_lines.append(f"{stamp} GITHUB THREAT {repo} {name}: {', '.join(sorted(hits))} ({'; '.join(labels)})")
            if a.fix and not existing:  # auto-fix of brand-new pushes (off unless chosen in Settings)
                do_fix(repo, name, head, hits, old)

    if a.fix_existing:
        # Fix All on GitHub: reported branches that haven't moved since. With --approved, only the exact
        # branch versions the person saw in the preview; a branch pushed to since then is left alone.
        for key, f in list(findings.items()):
            if approved is not None and f"{key}|{f['sha']}" not in approved:
                continue
            if f["repo"] in repos_state and repos_state[f["repo"]]["branches"].get(f["branch"]) == f["sha"]:
                do_fix(f["repo"], f["branch"], f["sha"], {p: [tuple(x) for x in h] for p, h in f.get("hits", {}).items()}, f["sha"])

    state["baseline_done"] = True
    state["last_poll"] = stamp
    # keep the verdict cache bounded
    if len(scanner.verdicts) > 50000:
        for k in list(scanner.verdicts)[:-30000]:
            scanner.verdicts.pop(k)
    tmp = a.state + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh)
    os.replace(tmp, a.state)
    if a.log and log_lines:
        with open(a.log, "a") as fh:
            fh.write("\n".join(log_lines) + "\n")
    out["findings"] = sorted(findings.values(), key=lambda f: (f["repo"], f["branch"]))
    out["api_calls"] = gh.calls
    out["rate_remaining"] = int(gh.remaining) if gh.remaining is not None else None
    out["time"] = stamp
    print(json.dumps(out))


if __name__ == "__main__":
    main()
