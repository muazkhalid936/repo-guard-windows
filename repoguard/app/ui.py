"""RepoGuard window, tray icon and popups."""
import os, sys

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import (QApplication, QCheckBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
                               QMainWindow, QMenu, QMessageBox, QPushButton, QScrollArea, QSpinBox, QStackedWidget,
                               QSystemTrayIcon, QVBoxLayout, QWidget)

from .. import __version__, paths, protect
from .review import CAUTION, DANGER, MUTED, SAFE, CleanReviewDialog, GitHubReviewDialog, label, short

APP_NAME = "RepoGuard"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def shield_icon(color=SAFE, mark="✓"):
    pm = QPixmap(64, 64)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    path = QPainterPath()
    path.moveTo(32, 4)
    path.cubicTo(44, 10, 52, 11, 58, 11)
    path.cubicTo(58, 36, 50, 52, 32, 60)
    path.cubicTo(14, 52, 6, 36, 6, 11)
    path.cubicTo(12, 11, 20, 10, 32, 4)
    p.fillPath(path, QColor(color))
    p.setPen(QColor("white"))
    f = QFont()
    f.setPixelSize(30)
    f.setBold(True)
    p.setFont(f)
    p.drawText(pm.rect(), Qt.AlignCenter, mark)
    p.end()
    return QIcon(pm)


# ---------------------------------------------------------------- start with Windows

def startup_command():
    exe = sys.executable if getattr(sys, "frozen", False) else None
    return f'"{exe}" --background' if exe else None


def start_with_windows():
    if os.name != "nt":
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.QueryValueEx(k, APP_NAME)
            return True
    except OSError:
        return False


def set_start_with_windows(on):
    if os.name != "nt" or not startup_command():
        return
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if on:
            winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ, startup_command())
        else:
            try:
                winreg.DeleteValue(k, APP_NAME)
            except OSError:
                pass


# ---------------------------------------------------------------- building blocks

class Card(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(16, 14, 16, 14)
        self.lay.setSpacing(6)


def clear(layout):
    while layout.count():
        it = layout.takeAt(0)
        if it.widget():
            it.widget().deleteLater()
        elif it.layout():
            clear(it.layout())


def button(text, fn, danger=False, primary=False):
    b = QPushButton(text.replace("&", "&&"))  # a lone & would turn into a keyboard-shortcut underline
    b.clicked.connect(fn)
    b.setCursor(Qt.PointingHandCursor)
    if danger:
        b.setStyleSheet(f"background:{DANGER}; color:white; padding:6px 14px; border-radius:6px; font-weight:600")
    elif primary:
        b.setStyleSheet("background:#2f6fde; color:white; padding:6px 14px; border-radius:6px; font-weight:600")
    return b


class Page(QScrollArea):
    """A scrollable page that rebuilds itself from the model."""
    title = ""

    def __init__(self, win):
        super().__init__()
        self.win, self.model = win, win.model
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        inner = QWidget()
        self.body = QVBoxLayout(inner)
        self.body.setContentsMargins(28, 24, 28, 24)
        self.body.setSpacing(14)
        self.setWidget(inner)

    def header(self, title, subtitle, *buttons):
        row = QHBoxLayout()
        col = QVBoxLayout()
        col.addWidget(label(title, size=24, bold=True))
        col.addWidget(label(subtitle, color=MUTED))
        row.addLayout(col, 1)
        for b in buttons:
            row.addWidget(b, 0, Qt.AlignTop)
        self.body.addLayout(row)

    def refresh(self):
        clear(self.body)
        self.build()
        self.body.addStretch(1)

    def build(self):
        pass


# ---------------------------------------------------------------- pages

class Dashboard(Page):
    title = "Dashboard"

    def build(self):
        m = self.model
        if not m.settings["watch_dirs"]:
            self.header("Welcome to RepoGuard", "Choose the folder that holds your code, and RepoGuard keeps watching it for the git worm.")
            self.body.addWidget(button("Choose Folders…", self.win.choose_folders, primary=True), 0, Qt.AlignLeft)
            return
        n = len(m.active)
        status = ("Scanning…" if m.scanning else f"{n} threat{'s' if n != 1 else ''} found" if n else "Protected")
        self.header("Dashboard", f"Watching {len(m.settings['watch_dirs'])} folder(s) · last full scan {m.last_scan or 'not yet'}",
                    button("Scan Now", m.scan_full))
        c = Card()
        color = DANGER if n else SAFE
        c.lay.addWidget(label(("⚠ " if n else "✓ ") + status, size=22, bold=True, color=color))
        c.lay.addWidget(label(f"{m.files_checked:,} files checked in {len(m.repos)} projects", color=MUTED))
        if n:
            c.lay.addWidget(button("Review Threats", lambda: self.win.show_page("Threats"), danger=True), 0, Qt.AlignLeft)
        self.body.addWidget(c)
        row = QHBoxLayout()
        for title, value, col in [
            ("GitHub", f"{len(m.gh['findings'])} infected branch(es)" if m.gh["findings"] else ("Off" if not m.settings["gh_watch"] else "Clean"),
             DANGER if m.gh["findings"] else MUTED),
            ("This PC", f"{sum(1 for f in m.pc.get('findings', []) if f['severity'] == 'block')} threat(s)"
             if any(f["severity"] == "block" for f in m.pc.get("findings", [])) else "Clean", MUTED),
            ("Git protection", {"on": "On", "off": "Off", "other": "Off (another hooks folder)", "nogit": "Git not installed"}[protect.status()],
             SAFE if protect.status() == "on" else CAUTION)]:
            k = Card()
            k.lay.addWidget(label(title, color=MUTED))
            k.lay.addWidget(label(value, size=16, bold=True, color=col))
            row.addWidget(k)
        self.body.addLayout(row)
        if protect.status() != "on":
            k = Card()
            k.lay.addWidget(label("Turn on git protection", bold=True))
            k.lay.addWidget(label("Blocks any pull, fetch or clone that brings malware, before your files change. "
                                  "Works in the terminal, VS Code and GitHub Desktop.", color=MUTED))
            k.lay.addWidget(button("Turn On", self.win.turn_on_protection, primary=True), 0, Qt.AlignLeft)
            self.body.addWidget(k)
        if m.last_error:
            self.body.addWidget(label("⚠ " + m.last_error, color=CAUTION))


class Threats(Page):
    title = "Threats"

    def build(self):
        m = self.model
        btns = []
        if m.active:
            btns = [button("Mark All as False Alarm…", self.win.false_alarm),
                    button("Removing…" if m.cleaning else "Preparing review…" if m.previewing else "Review & Remove Malware…",
                           m.preview_clean, danger=True)]
            for b in btns[1:]:
                b.setEnabled(not (m.cleaning or m.previewing or m.scanning))
        sub = "Nothing needs your attention." if not m.active else f"{len(m.active)} in {m.threat_repo_count} project(s)"
        self.header("Threats", sub, *btns)
        if m.cleaning:
            self.body.addWidget(label("Removing malware. Re-fetching clean branches from GitHub can take a few minutes.", color=MUTED))
        if m.clean_summary:
            self.body.addWidget(self._result(m.clean_summary))
        if m.last_error and ("changed after you reviewed" in m.last_error or "failed" in m.last_error.lower()):
            self.body.addWidget(label("⚠ " + m.last_error, color=CAUTION))
        by_repo = {}
        for f in m.active:
            by_repo.setdefault(f["root"], []).append(f)
        for repo, fs in sorted(by_repo.items()):
            c = Card()
            c.lay.addWidget(label("📁 " + short(repo), size=15, bold=True))
            for f in sorted(fs, key=lambda x: x["path"]):
                where = f["where"].replace("branch:refs/remotes/", "GitHub copy ").replace("branch:refs/heads/", "branch ").replace(
                    "incoming:refs/remotes/", "incoming ").replace("folder", "files on disk")
                c.lay.addWidget(label(f"<b>{f['path']}</b> — {f['label']} <span style='color:{MUTED}'>({where})</span>"))
            self.body.addWidget(c)
        if m.reviews:
            c = Card()
            c.lay.addWidget(label("Worth a look (not blocked)", bold=True))
            for r in m.reviews[:15]:
                c.lay.addWidget(label(f"• {short(r['root'])} {r['path']}: {r['label']}", color=MUTED))
            self.body.addWidget(c)

    def _result(self, s):
        c = Card()
        ok = s.get("manual", 0) == 0
        c.lay.addWidget(label(("✓ " if ok else "⚠ ") + "Malware removed", size=16, bold=True, color=SAFE if ok else CAUTION))
        c.lay.addWidget(label(f"{s.get('files', 0)} files cleaned · {s.get('refs', 0)} branches fixed"
                              + (f" · {s['pushed']} GitHub branches fixed with a pushed cleanup commit" if s.get("pushed") else "")))
        for x in s.get("manual_items") or []:
            c.lay.addWidget(label("• needs a manual look: " + x, color=CAUTION))
        if s.get("kept_tags"):
            c.lay.addWidget(label(f"{s['kept_tags']} infected tags kept. Use Permanently to delete them.", color=MUTED))
        c.lay.addWidget(label("Originals are backed up in " + short(s.get("backup", "")), color=MUTED))
        return c


class GitHub(Page):
    title = "GitHub"

    def build(self):
        m = self.model
        g = m.gh
        btns = [button("Check Now", lambda: m.gh_poll(fix_existing=False))]
        if g["findings"]:
            b = button("Fixing…" if m.gh_running else "Preparing review…" if m.gh_previewing else "Review & Fix on GitHub…",
                       m.gh_preview, danger=True)
            b.setEnabled(not (m.gh_running or m.gh_previewing))
            btns.append(b)
        sub = ("Off. Turn it on in Settings." if not m.settings["gh_watch"] else
               f"Every {m.settings['gh_minutes']} min, checks every repo you can push to · last check {g.get('time') or 'not yet'}")
        self.header("GitHub", sub, *btns)
        if g.get("error"):
            self.body.addWidget(label("⚠ " + g["error"], color=CAUTION))
        if m.gh_last_fix:
            r = m.gh_last_fix
            c = Card()
            c.lay.addWidget(label(f"✓ {len(r.get('fixed', []))} GitHub branches fixed", bold=True, color=SAFE))
            for x in r.get("manual", [])[:8]:
                c.lay.addWidget(label("• " + x, color=CAUTION))
            self.body.addWidget(c)
        if not g["findings"]:
            self.body.addWidget(label("No infected branches on GitHub.", color=MUTED))
        for f in g["findings"]:
            c = Card()
            c.lay.addWidget(label(f"<b>{f['repo']}</b> · branch <code>{f['branch']}</code>", size=14))
            c.lay.addWidget(label(", ".join(f["files"]), color=MUTED))
            c.lay.addWidget(label(" · ".join(f["labels"]) + (" · infected before the watch started" if f.get("existing") else ""), size=11, color=MUTED))
            c.lay.addWidget(button("Open on GitHub", lambda _=False, f=f: os.startfile(f"https://github.com/{f['repo']}/tree/{f['branch']}")
                                   if os.name == "nt" else None), 0, Qt.AlignLeft)
            self.body.addWidget(c)


class ThisPC(Page):
    title = "This PC"

    def build(self):
        m = self.model
        pc = m.pc
        threats = [f for f in pc.get("findings", []) if f["severity"] == "block"]
        reviews = [f for f in pc.get("findings", []) if f["severity"] != "block"]
        self.boxes = []
        rm = button("Remove Selected…", self.fix_selected, danger=True)
        rm.setEnabled(not m.pc_running and bool(pc.get("findings")))
        self.header("This PC", ("Scanning…" if m.pc_running else f"Last check {pc.get('time') or 'not yet'}") +
                    " · Startup folder, registry Run keys, Scheduled Tasks, PowerShell profiles, VS Code settings, temp folders, running programs",
                    button("Scan Now", m.pc_scan), rm)
        if m.pc_results:
            c = Card()
            c.lay.addWidget(label("Last fix", bold=True))
            for r in m.pc_results:
                c.lay.addWidget(label(f"{'✓' if r.get('ok') else '⚠'} {short(str(r.get('path') or ''))}: {r.get('result')}",
                                      color=None if r.get("ok") else CAUTION))
            self.body.addWidget(c)
        for e in pc.get("errors", []):
            self.body.addWidget(label("⚠ " + e, color=CAUTION))
        for title, items, col in (("Threats", threats, DANGER), ("Worth a look", reviews, CAUTION)):
            if not items:
                continue
            c = Card()
            c.lay.addWidget(label(title, size=15, bold=True, color=col))
            for f in items:
                box = QCheckBox(f"{f['detail']}\n→ {f['fix']}")
                box.setChecked(f["severity"] == "block")
                self.boxes.append((f, box))
                c.lay.addWidget(box)
            self.body.addWidget(c)
        if not pc.get("findings"):
            self.body.addWidget(label("✓ Nothing suspicious on this PC.", size=15, bold=True, color=SAFE))
        inv = pc.get("inventory", [])
        if inv:
            c = Card()
            c.lay.addWidget(label(f"Everything that starts automatically ({len(inv)})", size=15, bold=True))
            for i in inv:
                row = QHBoxLayout()
                row.addWidget(label(f"<b>{i['label']}</b> <span style='color:{MUTED}'>· {i['where']}</span><br>"
                                    f"<span style='color:{MUTED}; font-size:11px'>{(i.get('command') or '')[:160]}</span>"), 1)
                row.addWidget(button("Turn Off…", lambda _=False, i=i: self.turn_off(i)))
                c.lay.addLayout(row)
            self.body.addWidget(c)

    def fix_selected(self):
        chosen = [f for f, b in self.boxes if b.isChecked()]
        if not chosen:
            return
        text = "\n\n".join(f"• {f['detail']}\n   → {f['fix']}" for f in chosen[:12])
        if len(chosen) > 12:
            text += f"\n\n…and {len(chosen) - 12} more"
        if QMessageBox.question(self, "Remove these?", f"RepoGuard will do exactly this:\n\n{text}\n\nEverything removed is backed up first.",
                                QMessageBox.Yes | QMessageBox.Cancel) == QMessageBox.Yes:
            self.model.pc_clean([f["id"] for f in chosen])

    def turn_off(self, i):
        if QMessageBox.question(self, "Turn off?", f"Turn off {i['label']} ({i['where']})?\n\nRuns: {i.get('command', '')[:300]}\n\n"
                                "It's backed up first, so it can be put back.", QMessageBox.Yes | QMessageBox.Cancel) == QMessageBox.Yes:
            self.model.pc_clean([i["id"]])


class Activity(Page):
    title = "Activity"

    def build(self):
        self.header("Activity", "Everything RepoGuard found, removed and scanned.", button("Open Log File", self.win.open_log))
        lines = self.model.activity()
        c = Card()
        for l in lines[:300]:
            col = DANGER if (" THREAT " in l or "MALWARE" in l or "GITHUB THREAT" in l) else SAFE if ("CLEANED" in l or "FIXED" in l) else None
            c.lay.addWidget(label(l, size=11, color=col, mono=True, select=True))
        if not lines:
            c.lay.addWidget(label("Nothing yet.", color=MUTED))
        self.body.addWidget(c)


class SettingsPage(Page):
    title = "Settings"

    def build(self):
        m, s = self.model, self.model.settings
        self.header("Settings", f"RepoGuard {__version__} for Windows")
        c = Card()
        c.lay.addWidget(label("Watched folders", size=15, bold=True))
        for d in s["watch_dirs"]:
            row = QHBoxLayout()
            row.addWidget(label(d, mono=True), 1)
            row.addWidget(button("Remove", lambda _=False, d=d: m.set_watch_dirs([x for x in s["watch_dirs"] if x != d])))
            c.lay.addLayout(row)
        c.lay.addWidget(button("Add Folder…", self.win.choose_folders), 0, Qt.AlignLeft)
        self.body.addWidget(c)

        c = Card()
        c.lay.addWidget(label("Git protection", size=15, bold=True))
        st = protect.status()
        c.lay.addWidget(label({"on": "On: pulls, fetches and clones that bring malware are blocked.",
                               "off": "Off.", "other": f"Off: git uses another hooks folder ({protect.current()}).",
                               "nogit": "Git isn't installed."}[st], color=SAFE if st == "on" else CAUTION))
        c.lay.addWidget(button("Turn Off", self.win.turn_off_protection) if st == "on" else button("Turn On", self.win.turn_on_protection, primary=True), 0, Qt.AlignLeft)
        self.body.addWidget(c)

        c = Card()
        c.lay.addWidget(label("GitHub watch", size=15, bold=True))
        w = QCheckBox("Check my GitHub repos for malware pushes (uses the GitHub CLI login: gh auth login)")
        w.setChecked(s["gh_watch"])
        w.toggled.connect(lambda v: (s.__setitem__("gh_watch", v), m.reschedule_github()))
        c.lay.addWidget(w)
        row = QHBoxLayout()
        row.addWidget(label("Check every", wrap=False))
        sp = QSpinBox()
        sp.setRange(1, 120)
        sp.setValue(int(s["gh_minutes"]))
        sp.valueChanged.connect(lambda v: (s.__setitem__("gh_minutes", v), m.reschedule_github()))
        row.addWidget(sp)
        row.addWidget(label("minutes", wrap=False))
        row.addStretch(1)
        c.lay.addLayout(row)
        a = QCheckBox("Fix new malware pushes automatically, without asking (a cleanup commit is pushed right away)")
        a.setChecked(s["gh_autofix"])
        a.toggled.connect(lambda v: s.__setitem__("gh_autofix", v))
        c.lay.addWidget(a)
        self.body.addWidget(c)

        c = Card()
        c.lay.addWidget(label("General", size=15, bold=True))
        p = QCheckBox("Show a popup when malware is found")
        p.setChecked(s["popups"])
        p.toggled.connect(lambda v: s.__setitem__("popups", v))
        c.lay.addWidget(p)
        pcw = QCheckBox(f"Check this PC every 30 minutes")
        pcw.setChecked(s["pc_watch"])
        pcw.toggled.connect(lambda v: s.__setitem__("pc_watch", v))
        c.lay.addWidget(pcw)
        sw = QCheckBox("Start RepoGuard when I sign in to Windows")
        sw.setChecked(start_with_windows())
        sw.setEnabled(os.name == "nt" and bool(startup_command()))
        sw.toggled.connect(set_start_with_windows)
        c.lay.addWidget(sw)
        c.lay.addWidget(label("Data folder: " + paths.support_dir(), size=11, color=MUTED, select=True))
        self.body.addWidget(c)


PAGES = [Dashboard, Threats, GitHub, ThisPC, Activity, SettingsPage]


class MainWindow(QMainWindow):
    def __init__(self, model):
        super().__init__()
        self.model, self.quitting = model, False
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(shield_icon())
        self.resize(1080, 700)
        root = QWidget()
        lay = QHBoxLayout(root)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(200)
        self.nav.setIconSize(QSize(18, 18))
        self.stack = QStackedWidget()
        self.pages = []
        for P in PAGES:
            page = P(self)
            self.pages.append(page)
            self.stack.addWidget(page)
            QListWidgetItem(P.title, self.nav)
        self.nav.currentRowChanged.connect(self._go)
        lay.addWidget(self.nav)
        lay.addWidget(self.stack, 1)
        self.setCentralWidget(root)
        self.setStyleSheet("""
            QListWidget#nav { border:none; padding-top:16px; font-size:14px; }
            QListWidget#nav::item { padding:9px 14px; border-radius:6px; margin:1px 8px; }
            QListWidget#nav::item:selected { background:#2f6fde; color:white; }
            QFrame#card { border:1px solid rgba(128,128,128,0.25); border-radius:12px; background:palette(base); }
        """)
        model.changed.connect(self.refresh)
        self.nav.setCurrentRow(0)

    def _go(self, i):
        self.stack.setCurrentIndex(i)
        self.refresh()

    def refresh(self):
        self.pages[self.stack.currentIndex()].refresh()
        n = len(self.model.active)
        self.nav.item(1).setText("Threats" + (f"  ({n})" if n else ""))

    def show_page(self, title):
        self.nav.setCurrentRow([P.title for P in PAGES].index(title))

    def closeEvent(self, e):
        if self.quitting:
            e.accept()
        else:
            e.ignore()
            self.hide()

    # -------- actions
    def choose_folders(self):
        d = QFileDialog.getExistingDirectory(self, "Choose the folder that holds your repos")
        if d:
            refused = self.model.set_watch_dirs(self.model.settings["watch_dirs"] + [d])
            if refused:
                QMessageBox.warning(self, "That folder is too broad to watch",
                                    "Choose the folder that holds your code (for example Documents\\GitHub), not your whole user folder or drive.")

    def false_alarm(self):
        if QMessageBox.question(self, "Mark as false alarms?", f"Mark {len(self.model.active)} findings as false alarms?\n\n"
                                "Only do this if you're sure this code is safe. RepoGuard stops warning about these exact file versions, "
                                "and warns again if they change.", QMessageBox.Yes | QMessageBox.Cancel) == QMessageBox.Yes:
            self.model.mark_false_alarm()

    def review_clean(self, plan):
        dlg = CleanReviewDialog(plan, self)
        if dlg.exec() == CleanReviewDialog.Accepted:
            self.model.remove_malware(permanent=dlg.mode == "permanent", fix_github=dlg.mode != "mac", expect=plan["fingerprint"])

    def review_github(self, plan):
        dlg = GitHubReviewDialog(plan, self)
        if dlg.exec() == GitHubReviewDialog.Accepted:
            self.model.gh_poll(fix_existing=True, approved=dlg.approved)

    def turn_on_protection(self):
        ok, msg = protect.install()
        if not ok and protect.status() == "other":
            if QMessageBox.question(self, "Replace git's hooks setting?", msg, QMessageBox.Yes | QMessageBox.Cancel) == QMessageBox.Yes:
                ok, msg = protect.install(force=True)
            else:
                return
        (QMessageBox.information if ok else QMessageBox.warning)(self, "Git protection", msg)
        self.refresh()

    def turn_off_protection(self):
        protect.uninstall()
        self.refresh()

    def open_log(self):
        if os.name == "nt" and os.path.exists(paths.LOG()):
            os.startfile(paths.LOG())


class Tray(QSystemTrayIcon):
    def __init__(self, app, win, model):
        super().__init__(shield_icon(), app)
        self.win, self.model = win, model
        self.setToolTip(APP_NAME)
        menu = QMenu()
        for text, fn in (("Open RepoGuard", self.open), ("Scan Now", model.scan_full), ("Check This PC", model.pc_scan)):
            a = QAction(text, menu)
            a.triggered.connect(fn)
            menu.addAction(a)
        menu.addSeparator()
        q = QAction("Quit RepoGuard", menu)
        q.triggered.connect(self.quit)
        menu.addAction(q)
        self.menu = menu
        self.setContextMenu(menu)
        self.activated.connect(lambda r: self.open() if r in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None)
        model.changed.connect(self.update_icon)
        self.update_icon()

    def update_icon(self):
        m = self.model
        bad = bool(m.active or m.gh["findings"] or any(f["severity"] == "block" for f in m.pc.get("findings", [])))
        self.setIcon(shield_icon(DANGER, "!") if bad else shield_icon())
        self.setToolTip(f"{APP_NAME}: " + ("threats found" if bad else "protected"))

    def open(self, page=None):
        self.win.show()
        self.win.raise_()
        self.win.activateWindow()
        if page:
            self.win.show_page(page)

    def quit(self):
        self.win.quitting = True
        self.model.stop()
        QApplication.quit()


def alert(win, model, tray, title, lines, page, footer):
    tray.showMessage(title, lines[0] if lines else "", QSystemTrayIcon.Critical, 10000)
    if not model.settings["popups"]:
        return
    box = QMessageBox(QMessageBox.Critical, title, "\n".join(lines[:6]) + ("\n…and more." if len(lines) > 6 else "") + "\n\n" + footer)
    box.setWindowIcon(shield_icon(DANGER, "!"))
    review = box.addButton("Review", QMessageBox.AcceptRole)
    box.addButton("Dismiss", QMessageBox.RejectRole)
    box.setWindowFlag(Qt.WindowStaysOnTopHint)
    box.exec()
    if box.clickedButton() is review:
        tray.open(page)


def wire_alerts(win, model, tray):
    model.new_threats.connect(lambda found: alert(
        win, model, tray, "Malware warning: suspicious code found",
        [f"• {os.path.basename(f['root'])}/{f['path']}: {f['label']}" for f in found], "Threats",
        "Don't open this project in VS Code, run npm commands, or click Pull or Merge. RepoGuard hasn't run any of this code."))
    model.new_github.connect(lambda found, fixed: alert(
        win, model, tray, "Malware pushed to GitHub" + (" and removed" if fixed else ""),
        [f"• {f['repo']} · {f['branch']}: {', '.join(f['files'][:3])}" for f in found], "GitHub",
        "Someone with access to your GitHub pushed this. Don't pull these branches until they're clean, and check which tokens or machines can push."))
    model.new_pc.connect(lambda found: alert(
        win, model, tray, "Malware found on this PC", [f"• {f['detail'][:200]}" for f in found], "This PC",
        "Open This PC to remove it. Everything removed is backed up first."))
    model.plan_ready.connect(win.review_clean)
    model.gh_plan_ready.connect(win.review_github)
