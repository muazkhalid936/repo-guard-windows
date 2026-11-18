"""A tiny stand-in for the GitHub REST API, backed by local bare repos, for testing github_watch.py.
Usage: mock_github.py PORT REPOS_DIR   (repo "acme/app" lives at REPOS_DIR/acme/app.git)"""
import base64, hashlib, json, os, re, subprocess, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, unquote

PORT, ROOT = int(sys.argv[1]), sys.argv[2]
PROTECTED = set(os.environ.get("MOCK_PROTECTED", "").split(","))


def git(repo, *args, data=None):
    p = subprocess.run(["git", "-C", os.path.join(ROOT, repo + ".git"), *args], input=data, capture_output=True)
    if p.returncode:
        raise RuntimeError(p.stderr.decode())
    return p.stdout


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, obj=None, etag=None):
        body = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-RateLimit-Remaining", "4999")
        if etag:
            self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n)) if n else {}

    def do_GET(self):
        u = urlparse(self.path)
        p = unquote(u.path)
        if p == "/user/repos":
            repos = []
            for owner in sorted(os.listdir(ROOT)):
                for r in sorted(os.listdir(os.path.join(ROOT, owner))):
                    repos.append({"full_name": f"{owner}/{r[:-4]}", "archived": False, "permissions": {"push": True}})
            return self.send(200, repos)
        m = re.match(r"^/repos/([^/]+/[^/]+)/(.*)$", p)
        if not m:
            return self.send(404, {"message": "Not Found"})
        repo, rest = m.groups()
        if rest == "branches":
            out = git(repo, "for-each-ref", "--format=%(refname:strip=2) %(objectname)", "refs/heads").decode()
            items = [{"name": l.split()[0], "commit": {"sha": l.split()[1]}} for l in out.splitlines()]
            etag = '"' + hashlib.sha1(json.dumps(items).encode()).hexdigest() + '"'
            if self.headers.get("If-None-Match") == etag:
                return self.send(304)
            return self.send(200, items, etag)
        if rest.startswith("compare/"):
            old, new = rest[len("compare/"):].split("...")
            out = git(repo, "diff", "--raw", "--no-renames", "-z", old, new).split(b"\0")
            files = []
            for i in range(0, len(out) - 1, 2):
                meta = out[i].decode().split()
                files.append({"filename": out[i + 1].decode(), "sha": meta[3],
                              "status": "removed" if meta[4] == "D" else "modified"})
            return self.send(200, {"files": files})
        if rest.startswith("git/trees/"):
            sha = rest[len("git/trees/"):]
            out = git(repo, "ls-tree", "-r", "-l", sha).decode().splitlines()
            tree = []
            for l in out:
                meta, path = l.split("\t", 1)
                mode, typ, s, size = meta.split()
                tree.append({"path": path, "mode": mode, "type": typ, "sha": s, "size": int(size) if size != "-" else None})
            return self.send(200, {"tree": tree})
        if rest.startswith("git/blobs/"):
            data = git(repo, "cat-file", "blob", rest[len("git/blobs/"):])
            return self.send(200, {"content": base64.b64encode(data).decode(), "encoding": "base64"})
        if rest.startswith("git/commits/"):
            sha = rest[len("git/commits/"):]
            tree = git(repo, "rev-parse", sha + "^{tree}").decode().strip()
            return self.send(200, {"sha": sha, "tree": {"sha": tree}})
        return self.send(404, {"message": "Not Found"})

    def do_POST(self):
        p = unquote(urlparse(self.path).path)
        repo, rest = re.match(r"^/repos/([^/]+/[^/]+)/(.*)$", p).groups()
        b = self.body()
        if rest == "git/blobs":
            sha = git(repo, "hash-object", "-w", "--stdin", data=base64.b64decode(b["content"])).decode().strip()
            return self.send(201, {"sha": sha})
        if rest == "git/trees":
            env_index = os.path.join(ROOT, f".idx-{os.getpid()}")
            env = dict(os.environ, GIT_INDEX_FILE=env_index)
            g = lambda *a, data=None: subprocess.run(["git", "-C", os.path.join(ROOT, repo + ".git"), *a], input=data,
                                                     capture_output=True, env=env, check=True).stdout
            g("read-tree", b["base_tree"])
            for e in b["tree"]:
                if e["sha"] is None:
                    g("update-index", "--index-info", data=f"0 {'0' * 40}\t{e['path']}\n".encode())
                else:
                    g("update-index", "--add", "--cacheinfo", f"{e['mode']},{e['sha']},{e['path']}")
            sha = g("write-tree").decode().strip()
            os.unlink(env_index)
            return self.send(201, {"sha": sha})
        if rest == "git/commits":
            args = ["commit-tree", b["tree"], "-m", b["message"]]
            for par in b["parents"]:
                args += ["-p", par]
            env = dict(os.environ, GIT_AUTHOR_NAME="tester", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="tester", GIT_COMMITTER_EMAIL="t@t")
            sha = subprocess.run(["git", "-C", os.path.join(ROOT, repo + ".git"), *args], capture_output=True, env=env, check=True).stdout.decode().strip()
            return self.send(201, {"sha": sha})
        return self.send(404, {"message": "Not Found"})

    def do_PATCH(self):
        p = unquote(urlparse(self.path).path)
        repo, branch = re.match(r"^/repos/([^/]+/[^/]+)/git/refs/heads/(.*)$", p).groups()
        b = self.body()
        if branch in PROTECTED:
            return self.send(422, {"message": "Protected branch update failed"})
        cur = git(repo, "rev-parse", "refs/heads/" + branch).decode().strip()
        if not b.get("force"):
            r = subprocess.run(["git", "-C", os.path.join(ROOT, repo + ".git"), "merge-base", "--is-ancestor", cur, b["sha"]])
            if r.returncode:
                return self.send(422, {"message": "Update is not a fast forward"})
        git(repo, "update-ref", "refs/heads/" + branch, b["sha"], cur)
        return self.send(200, {"object": {"sha": b["sha"]}})


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
