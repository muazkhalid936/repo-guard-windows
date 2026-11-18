"""RepoGuard's background work: scans, folder watching, the GitHub watch and the PC checks.

Every scan runs the core scripts in a separate process (see paths.core_cmd), never in the app itself,
so nothing from a scanned repo can be loaded into RepoGuard.
"""
import datetime, json, os, subprocess, sys, threading, time

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Signal, Slot

from .. import paths, protect

NO_WINDOW = 0x08000000 if os.name == "nt" else 0
FULL_SCAN_HOURS = 6
PC_SCAN_MINUTES = 30
SKIP_PARTS = {"node_modules", ".next", "dist", "build", ".venv", "venv", "__pycache__", ".cache"}


def run_core(name, args, timeout=1800):
    """(returncode, parsed JSON or None, stderr text) for one core script."""
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    try:
        p = subprocess.run(paths.core_cmd(name) + list(args), capture_output=True, timeout=timeout, env=env,
                           cwd=os.path.expanduser("~"), creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, None, str(e)
    out = p.stdout.decode("utf8", "replace")
    data = None
    for line in reversed(out.splitlines()):
        if line.startswith("{"):
            try:
                data = json.loads(line)
                break
            except ValueError:
                pass
    return p.returncode, data, p.stderr.decode("utf8", "replace")


def log(msg):
    try:
        with open(paths.LOG(), "a", encoding="utf8") as fh:
            fh.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} {msg}\n")
    except OSError:
        pass


class Settings:
    DEFAULTS = {"watch_dirs": [], "popups": True, "gh_watch": True, "gh_minutes": 3, "gh_autofix": False,
                "pc_watch": True, "setup_done": False}

    def __init__(self):
        self.path = paths.data("settings.json")
        try:
            self.values = dict(self.DEFAULTS, **json.load(open(self.path, encoding="utf8")))
        except (OSError, ValueError):
            self.values = dict(self.DEFAULTS)

    def __getitem__(self, k):
        return self.values[k]

    def __setitem__(self, k, v):
        self.values[k] = v
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf8") as fh:
            json.dump(self.values, fh, indent=1)
        os.replace(tmp, self.path)


class _Signals(QObject):
    done = Signal(object)


class Job(QRunnable):
    def __init__(self, fn, on_done):
        super().__init__()
        self.fn, self.sig = fn, _Signals()
        self.sig.done.connect(on_done)

    def run(self):
        try:
            res = self.fn()
        except Exception as e:  # report, never crash the app
            res = {"error": f"{type(e).__name__}: {e}"}
        self.sig.done.emit(res)


TOO_BROAD = lambda d: os.path.normcase(os.path.abspath(d)) in {  # noqa: E731
    os.path.normcase(os.path.abspath(x)) for x in (os.path.expanduser("~"), "C:\\", "/", os.environ.get("SystemRoot", "C:\\Windows"))}


class Model(QObject):
    changed = Signal()
    new_threats = Signal(list)           # repo findings
    new_github = Signal(list, list)      # new findings, auto-fixed
    new_pc = Signal(list)                # PC findings
    plan_ready = Signal(object)          # local Remove Malware review
    gh_plan_ready = Signal(object)       # Fix on GitHub review
    _paths_seen = Signal()

    def __init__(self):
        super().__init__()
        self.settings = Settings()
        self.active, self.repos, self.reviews = [], [], []
        self.files_checked, self.last_scan, self.errors = 0, None, []
        self.scanning = self.cleaning = self.previewing = False
        self.clean_summary, self.last_error = None, None
        self.gh = {"findings": [], "time": None, "error": None, "rate_remaining": None}
        self.gh_running = self.gh_previewing = False
        self.gh_last_fix = None
        self.pc = {"findings": [], "inventory": [], "errors": [], "time": None}
        self.pc_running, self.pc_results = False, None
        self.queue = QThreadPool()      # engine + cleaner, one at a time (they share state.json)
        self.queue.setMaxThreadCount(1)
        self.ghq = QThreadPool()
        self.ghq.setMaxThreadCount(1)
        self.pcq = QThreadPool()
        self.pcq.setMaxThreadCount(1)
        self._pending, self._lock = set(), threading.Lock()
        self._observer = None
        self._debounce = QTimer(self, singleShot=True, interval=3000, timeout=self._flush_events)
        self._paths_seen.connect(self._debounce.start)
        self._full_timer = QTimer(self, interval=FULL_SCAN_HOURS * 3600 * 1000, timeout=self.scan_full)
        self._pc_timer = QTimer(self, interval=PC_SCAN_MINUTES * 60 * 1000, timeout=self.pc_scan)
        self._gh_timer = QTimer(self, timeout=self.gh_poll)
        self._load_saved()

    # ------------------------------------------------------------ lifecycle
    def start(self):
        self.watch()
        self._full_timer.start()
        if self.settings["pc_watch"]:
            self._pc_timer.start()
            QTimer.singleShot(15000, self.pc_scan)
        self.reschedule_github()
        if self.settings["watch_dirs"]:
            QTimer.singleShot(2000, self.scan_full)

    def stop(self):
        if self._observer:
            self._observer.stop()

    def _state(self):
        return paths.data("state.json")

    def _engine_args(self, mode, extra=()):
        args = [mode]
        for d in self.settings["watch_dirs"]:
            args += ["--watch", d]
        return args + ["--state", self._state(), "--rules", paths.RULES, "--log", paths.LOG(), *extra]

    def _load_saved(self):
        if os.path.exists(self._state()):
            rc, data, err = run_core("engine", self._engine_args("status"), timeout=120)
            if data:
                self._apply_scan(data, notify=False)
        try:
            gh = json.load(open(paths.data("github-watch.json"), encoding="utf8"))
            self.gh["findings"] = sorted(gh.get("findings", {}).values(), key=lambda f: (f["repo"], f["branch"]))
            self.gh["time"] = gh.get("last_poll")
        except (OSError, ValueError):
            pass
        try:
            self.pc = json.load(open(paths.data("pc-report.json"), encoding="utf8"))
        except (OSError, ValueError):
            pass

    # ------------------------------------------------------------ folders
    def set_watch_dirs(self, dirs):
        refused = [d for d in dirs if TOO_BROAD(d)]
        keep = sorted({os.path.abspath(d) for d in dirs if not TOO_BROAD(d)})
        self.settings["watch_dirs"] = keep
        self.settings["setup_done"] = bool(keep)
        self.watch()
        self.scan_full()
        return refused

    def watch(self):
        if self._observer:
            self._observer.stop()
            self._observer = None
        dirs = [d for d in self.settings["watch_dirs"] if os.path.isdir(d)]
        if not dirs:
            return
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            log("FOLDER WATCH unavailable (watchdog missing); relying on scheduled scans")
            return
        model = self

        class Handler(FileSystemEventHandler):
            def on_any_event(self, ev):
                for p in {getattr(ev, "src_path", ""), getattr(ev, "dest_path", "")}:
                    if not p:
                        continue
                    parts = set(p.replace("\\", "/").split("/"))
                    if parts & SKIP_PARTS:
                        continue
                    with model._lock:
                        model._pending.add(p)
                    model._paths_seen.emit()

        obs = Observer()
        for d in dirs:
            try:
                obs.schedule(Handler(), d, recursive=True)
            except OSError as e:
                log(f"FOLDER WATCH couldn't watch {d}: {e}")
        obs.daemon = True
        obs.start()
        self._observer = obs

    @Slot()
    def _flush_events(self):
        with self._lock:
            batch, self._pending = sorted(self._pending), set()
        if not batch:
            return
        f = paths.data("event-paths.json")

        def work():
            with open(f, "w", encoding="utf8") as fh:
                json.dump(batch[:5000], fh)
            rc, data, err = run_core("engine", self._engine_args("event", ["--paths-file", f]), timeout=600)
            return data or {"error": err[-400:]}
        self.queue.start(Job(work, lambda r: self._apply_scan(r, notify=True)))

    # ------------------------------------------------------------ scans
    def scan_full(self):
        if not self.settings["watch_dirs"] or self.scanning:
            return
        self.scanning = True
        self.changed.emit()

        def work():
            rc, data, err = run_core("engine", self._engine_args("full"))
            return data or {"error": "The scan failed: " + err.strip()[-400:]}
        self.queue.start(Job(work, self._scan_done))

    def _scan_done(self, r):
        self.scanning = False
        self._apply_scan(r, notify=True)

    def _apply_scan(self, r, notify):
        if r.get("error"):
            self.last_error = r["error"]
            log("ENGINE ERROR: " + r["error"])
        else:
            self.active = r.get("active", [])
            self.repos = r.get("repo_info") or self.repos
            self.reviews = list(reversed(r.get("recent_reviews") or []))
            self.errors = r.get("errors") or []
            self.last_error = self.errors[0] if self.errors else None
            lf = r.get("last_full")
            if lf:
                self.files_checked = lf.get("files", self.files_checked)
                self.last_scan = lf.get("time")
            if notify and r.get("new"):
                self.new_threats.emit(r["new"])
        self.changed.emit()

    def mark_false_alarm(self):
        def work():
            run_core("engine", ["ignore-active", "--state", self._state()], timeout=60)
            rc, data, err = run_core("engine", self._engine_args("full"))
            return data or {"error": err[-400:]}
        self.queue.start(Job(work, lambda r: self._apply_scan(r, notify=False)))

    # ------------------------------------------------------------ remove malware (review first)
    def preview_clean(self):
        if self.previewing:
            return
        self.previewing = True
        self.changed.emit()

        def work():
            rc, data, err = run_core("cleaner", ["--state", self._state(), "--rules", paths.RULES, "--preview"], timeout=900)
            if rc != 0 or not data:
                log("CLEANER PREVIEW ERROR: " + err[-400:])
                return {"error": "Couldn't prepare the review. See Activity for details."}
            return data

        def done(r):
            self.previewing = False
            if r.get("error"):
                self.last_error = r["error"]
            else:
                self.plan_ready.emit(r)
            self.changed.emit()
        self.queue.start(Job(work, done))

    def remove_malware(self, permanent=False, fix_github=False, expect=""):
        self.cleaning, self.clean_summary = True, None
        self.changed.emit()

        def work():
            args = ["--state", self._state(), "--rules", paths.RULES, "--backup", paths.data("quarantine"), "--log", paths.LOG()]
            if permanent:
                args.append("--permanent")
            if fix_github:
                args.append("--fix-github")
            if expect:
                args += ["--expect", expect]
            rc, data, err = run_core("cleaner", args)
            if rc == 3:
                return {"error": "The threats changed after you reviewed them, so nothing was removed. "
                                 "Click Review & Remove Malware again to see the new list."}
            if rc != 0 or not data:
                log("CLEANER ERROR: " + err[-600:])
                return {"error": "Removing malware failed. See Activity for details."}
            rc2, scan, err2 = run_core("engine", self._engine_args("full"))
            data["_scan"] = scan
            return data

        def done(r):
            self.cleaning = False
            if r.get("error"):
                self.last_error = r["error"]
            else:
                self.clean_summary = r
                if r.get("_scan"):
                    self._apply_scan(r["_scan"], notify=False)
            self.changed.emit()
        self.queue.start(Job(work, done))

    # ------------------------------------------------------------ GitHub watch
    def reschedule_github(self):
        self._gh_timer.stop()
        if self.settings["gh_watch"]:
            self._gh_timer.start(max(1, int(self.settings["gh_minutes"])) * 60 * 1000)
            QTimer.singleShot(20000, self.gh_poll)

    def gh_poll(self, fix_existing=False, approved=None):
        if self.gh_running or not (self.settings["gh_watch"] or fix_existing):
            return
        self.gh_running = True
        self.changed.emit()

        def work():
            args = ["poll", "--rules", paths.RULES, "--state", paths.data("github-watch.json"), "--log", paths.LOG()]
            if self.settings["gh_autofix"]:
                args.append("--fix")
            if fix_existing:
                args.append("--fix-existing")
            if approved is not None:
                f = paths.data("github-approved.json")
                with open(f, "w", encoding="utf8") as fh:
                    json.dump(list(approved), fh)
                args += ["--approved", f]
            rc, data, err = run_core("github_watch", args, timeout=1500)
            if data is None:
                return {"error": "GitHub check failed: " + err.strip()[-300:]}
            return data

        def done(r):
            self.gh_running = False
            if r.get("error") and not r.get("findings"):
                self.gh["error"] = r["error"]
            else:
                self.gh = {"findings": r.get("findings", []), "time": r.get("time"), "error": None,
                           "rate_remaining": r.get("rate_remaining")}
                if fix_existing:
                    self.gh_last_fix = r
                elif r.get("new_findings") or r.get("fixed"):
                    self.new_github.emit(r.get("new_findings", []), r.get("fixed", []))
            self.changed.emit()
        self.ghq.start(Job(work, done))

    def gh_preview(self):
        if self.gh_previewing or self.gh_running:
            return
        self.gh_previewing = True
        self.changed.emit()

        def work():
            rc, data, err = run_core("github_watch", ["preview", "--rules", paths.RULES, "--state", paths.data("github-watch.json")], timeout=900)
            return data if data and "branches" in data else {"error": "Couldn't read the branches from GitHub: " + err.strip()[-200:]}

        def done(r):
            self.gh_previewing = False
            if r.get("error"):
                self.gh["error"] = r["error"]
            else:
                self.gh_plan_ready.emit(r)
            self.changed.emit()
        self.ghq.start(Job(work, done))

    # ------------------------------------------------------------ this PC
    def pc_scan(self, notify=True):
        if self.pc_running:
            return
        self.pc_running = True
        self.changed.emit()
        before = {f["id"] for f in self.pc.get("findings", [])}

        def work():
            rc, data, err = run_core("pc_agent", ["scan", "--backup", paths.data("quarantine"), "--own-hooks", protect.hooks_dir()], timeout=900)
            return data or {"error": "PC scan failed: " + err.strip()[-300:]}

        def done(r):
            self.pc_running = False
            if r.get("error"):
                self.pc["errors"] = [r["error"]]
            else:
                self._save_pc(r)
                new = [f for f in r["findings"] if f["id"] not in before and f["severity"] == "block"]
                if new:
                    log(f"PC SCAN: {len(new)} new threat(s): " + "; ".join(f["detail"][:120] for f in new[:5]))
                    if notify:
                        self.new_pc.emit(new)
            self.changed.emit()
        self.pcq.start(Job(work, done))

    def _save_pc(self, r):
        self.pc = {"findings": r.get("findings", []), "inventory": r.get("inventory", []), "errors": r.get("errors", []),
                   "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        try:
            with open(paths.data("pc-report.json"), "w", encoding="utf8") as fh:
                json.dump(self.pc, fh)
        except OSError:
            pass

    def pc_clean(self, ids):
        if self.pc_running or not ids:
            return
        self.pc_running = True
        self.changed.emit()

        def work():
            rc, data, err = run_core("pc_agent", ["clean", "--backup", paths.data("quarantine"), "--own-hooks", protect.hooks_dir(), "--ids", *ids], timeout=900)
            return data or {"error": "Fixing failed: " + err.strip()[-300:]}

        def done(r):
            self.pc_running = False
            if r.get("error"):
                self.pc["errors"] = [r["error"]]
            else:
                self.pc_results = r.get("results", [])
                for x in self.pc_results:
                    log(f"PC FIXED {x.get('path')}: {x.get('result')}")
                self._save_pc(r)
            self.changed.emit()
        self.pcq.start(Job(work, done))

    # ------------------------------------------------------------ activity
    def activity(self, limit=400):
        try:
            with open(paths.LOG(), encoding="utf8", errors="replace") as fh:
                lines = fh.readlines()[-limit:]
        except OSError:
            return []
        return [l.rstrip("\n") for l in reversed(lines)]

    @property
    def threat_repo_count(self):
        return len({f["root"] for f in self.active})
