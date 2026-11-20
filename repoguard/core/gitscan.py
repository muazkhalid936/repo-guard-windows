#!/usr/bin/python3 -I
"""Scan a git revision for the malware patterns seen in the Nov 2026 incident.

Reads git objects only. It never runs, imports or checks out repo content.

  git-scan-malware                    scan HEAD
  git-scan-malware --rev origin/main  scan another revision
  git-scan-malware --range A..B       also scan every file version added in A..B

Exit codes: 0 no blocking findings, 1 blocking findings, 2 scan could not run.
"""
import argparse, os, re, subprocess, sys

KNOWN = re.compile(
    rb"cNyiIhxm[K]lTvaNSt|rCLdg[g]d\$ZUlOU|FHptxE[V]PmEWNHCYlL|hLsNetS[E]CrqLyGkrjdgtIJ|iHnmz[E]bnHW"
    rb"|Fy_hvvQ[d]tanMSNmFvVBQC|mlCq[U]CKEc|global\.i\s*=\s*'A11|var z = '-67[5]2|rmcej[%]otb%|Cot[%]3t=shtP|var bx\s*=\s*'-11647|0x3b1574417524c11a7403c4b232CAcBb320Cce[B]C6"
)
HOSTS = re.compile(rb"jsonkeeper\.com|npoint\.io|ipcheck[-]six")
AUTORUN = re.compile(rb'runOn"?\s*:\s*"folderOpen"|allowAutomaticTasks"?\s*:\s*("on"|true)')
LOADER = re.compile(rb'"[\w:.-]+"\s*:\s*"node\s+(?:\./)?init\b')
MARKER = re.compile(rb"^(?:config\.bat|temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json)\s*$", re.M)
HEADER = re.compile(rb"createRequire\(import\.meta\.url\)\s*;?\s*\r?\n\s*var module\s*=")
OFFSCREEN = re.compile(rb"\S[ \t]{100,}[^\s/*#<-]")
OBF_LOOP = re.compile(rb"while\s*\(\s*!!\[\]\s*\)")
HEX_ID = re.compile(rb"_0x[0-9a-f]{4,}")
EVAL_B64 = re.compile(rb"(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from)\s*\(")
INSTALL = re.compile(rb'"(preinstall|install|postinstall|prepare)"\s*:\s*"([^"]{0,80})')
CODE = re.compile(r"\.(?:c|m)?[jt]sx?$|\.json$|\.vue$|\.py$|\.sh$|(?:^|/)init$")
MEDIA = re.compile(r"\.(?:png|jpe?g|gif|webp|ico|woff2?|ttf|otf|eot|mp3|mp4|pdf)$", re.I)
BAD_PATH = re.compile(r"\.orc$|(?:^|/)init$|(?:^|/)config\.bat$|(?:^|/)temp_(?:auto|interactive)_push\.bat$")
WARN_PATH = re.compile(r"(?:^|/)\.vscode/tasks\.json$|(?:^|/)\.husky/|(?:^|/)\.npmrc$|(?:^|/)\.gitmodules$|^\.github/workflows/")
VENDORED = re.compile(r"(?:^|/)node_modules/|(?:^|/)vendor/|\.min\.[jc]ss?$|\.map$")
SKIP = re.compile(r"(?:^|/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|composer\.lock)$")
MAX = 5_000_000


def git(*a, **k):
    return subprocess.run(["git", *a], capture_output=True, **k)


def check(path, data):
    """Return (blocking, warnings) for one file version."""
    block, warn = [], []
    if BAD_PATH.search(path):
        block.append("suspicious file name")
    if WARN_PATH.search(path):
        warn.append("can run code automatically, review it")
    if data is None or SKIP.search(path):
        return block, warn
    if b"\0" in data[:8000]:
        return block, warn
    if MEDIA.search(path) and re.search(rb"function\s*\(|require\(|\bvar\s", data[:8000]):
        block.append("code disguised as a media or font file")
    if KNOWN.search(data):
        block.append("known malware code")
    if AUTORUN.search(data):
        block.append("runs automatically when the folder opens")
    if os.path.basename(path) == ".gitignore" and MARKER.search(data):
        block.append("malware marker line in .gitignore")
    if HEADER.search(data):
        block.append("leftover malware loader lines")
    if HOSTS.search(data):
        block.append("known malware server address")
    if EVAL_B64.search(data):
        block.append("runs encoded code")
    if os.path.basename(path) == "package.json":
        if LOADER.search(data):
            block.append("npm script runs a hidden loader")
        for m in INSTALL.finditer(data):
            if not VENDORED.search(path):
                warn.append(f"install script {m.group(1).decode()}: {m.group(2).decode('utf8', 'replace')}")
    if CODE.search(path) and not VENDORED.search(path):
        if OFFSCREEN.search(data):
            block.append("code hidden far off-screen")
        if OBF_LOOP.search(data) or len(HEX_ID.findall(data)) >= 20:
            block.append("obfuscated code")
    return block, warn


def read_blobs(items):
    """Yield (sha, path, bytes or None). Oversized blobs are checked by name only."""
    if not items:
        return
    shas = list(dict.fromkeys(s for s, _ in items))
    sizes = {}
    for line in git("cat-file", "--batch-check", input="\n".join(shas).encode()).stdout.decode().splitlines():
        f = line.split()
        if len(f) == 3 and f[1] == "blob":
            sizes[f[0]] = int(f[2])
    want = [s for s in shas if sizes.get(s, MAX + 1) <= MAX]
    data = {}
    if want:
        out = git("cat-file", "--batch", input="\n".join(want).encode()).stdout
        i = 0
        while i < len(out):
            nl = out.index(b"\n", i)
            head = out[i:nl].split()
            size = int(head[2])
            data[head[0].decode()] = out[nl + 1:nl + 1 + size]
            i = nl + 2 + size
    for s, p in items:
        if s in sizes:
            yield s, p, data.get(s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--range", dest="rng")
    ap.add_argument("--quiet", action="store_true", help="print nothing when clean")
    a = ap.parse_args()

    tree = git("ls-tree", "-r", a.rev)
    if tree.returncode:
        print(f"git-scan-malware: cannot read {a.rev}: {tree.stderr.decode()[:200]}", file=sys.stderr)
        return 2
    items = []
    for line in tree.stdout.decode("utf8", "replace").splitlines():
        meta, path = line.split("\t", 1)
        f = meta.split()
        if f[1] == "blob":
            items.append((f[2], path))
    current = {s for s, _ in items}
    hist = []
    if a.rng:
        for line in git("rev-list", "--objects", *a.rng.split()).stdout.decode("utf8", "replace").splitlines():
            f = line.split(" ", 1)
            if len(f) == 2 and f[0] not in current:
                hist.append((f[0], f[1]))

    blocking, warnings, hist_hits, count = [], [], [], 0
    for s, p, d in read_blobs(items):
        count += 1
        b, w = check(p, d)
        blocking += [(p, x) for x in b]
        warnings += [(p, x) for x in w]
    for s, p, d in read_blobs(hist):
        count += 1
        b, _ = check(p, d)
        hist_hits += [(p, x) for x in b]

    if blocking or hist_hits:
        print("\n" + "!" * 68)
        print(f"  MALWARE WARNING: suspicious code in {a.rev}. Do NOT open or run this code.")
        print("!" * 68)
        for p, x in blocking[:25]:
            print(f"  BLOCK   {p[:70]}  ({x})")
        for p, x in hist_hits[:25]:
            print(f"  HISTORY {p[:70]}  ({x})")
        print()
    for p, x in warnings[:15]:
        print(f"  review  {p[:70]}  ({x})")
    if not (blocking or hist_hits) and not a.quiet:
        print(f"git-scan-malware: clean, {count} file versions checked in {a.rev}")
    return 1 if blocking or hist_hits else 0


if __name__ == "__main__":
    sys.exit(main())
