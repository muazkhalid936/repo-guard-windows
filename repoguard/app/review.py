"""Review before removing: every change is listed, with the exact code removed, and nothing runs
until the person approves. Used for Remove Malware (this PC) and Fix on GitHub."""
import html, os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QButtonGroup, QCheckBox, QDialog, QFrame, QHBoxLayout, QLabel, QPushButton, QRadioButton,
                               QScrollArea, QTextBrowser, QVBoxLayout, QWidget)

DANGER, CAUTION, SAFE, MUTED = "#d63333", "#e68c1f", "#1c9e66", "#8a8a8a"
HOME = os.path.expanduser("~")


def short(p):
    return p.replace(HOME, "~", 1) if p.startswith(HOME) else p


def label(text, size=None, bold=False, color=None, wrap=True, mono=False, select=False):
    l = QLabel(text)
    l.setWordWrap(wrap)
    css = []
    if size:
        css.append(f"font-size:{size}px")
    if bold:
        css.append("font-weight:600")
    if color:
        css.append(f"color:{color}")
    if mono:
        css.append("font-family:Consolas,'Cascadia Mono',Menlo,monospace")
    l.setStyleSheet(";".join(css))
    if select:
        l.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return l


def summary_line(items):
    d = sum(1 for i in items if i["action"] == "delete")
    c = sum(1 for i in items if i["action"] == "clean")
    m = sum(1 for i in items if i["action"] == "manual")
    parts = []
    if d:
        parts.append(f"delete {d} file{'s' if d != 1 else ''}")
    if c:
        parts.append(f"cut malware out of {c} file{'s' if c != 1 else ''}")
    s = ("RepoGuard will " + " and ".join(parts) + ".") if parts else "Nothing can be removed automatically."
    if m:
        s += f" {m} will be left for you to check by hand."
    return s


class ItemRow(QFrame):
    """One file: what happens to it, why, where it was found, and the code being removed."""

    def __init__(self, item, start_open=False):
        super().__init__()
        act = item["action"]
        icon, color = {"delete": ("🗑", DANGER), "clean": ("✂", CAUTION)}.get(act, ("✋", MUTED))
        head = {"delete": "Delete the whole file. All of it is malware.",
                "clean": f"Cut out {item['removed_chars']:,} characters of malware and keep the rest of the file."}.get(
            act, "Left unchanged; needs a manual look: " + (item.get("why") or ""))
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 6, 0, 6)
        ic = label(icon, size=18, color=color, wrap=False)
        ic.setFixedWidth(26)
        ic.setAlignment(Qt.AlignTop)
        row.addWidget(ic)
        col = QVBoxLayout()
        col.setSpacing(3)
        row.addLayout(col, 1)
        col.addWidget(label(item["path"], bold=True, mono=True, select=True))
        col.addWidget(label(head))
        col.addWidget(label("Found: " + " · ".join(item.get("found", [])), size=11, color=MUTED))
        col.addWidget(label("In: " + " · ".join(item.get("where", [])), size=11, color=MUTED))
        if item.get("notes"):
            col.addWidget(label("Changes: " + " · ".join(item["notes"]), size=11, color=MUTED))
        if item.get("removed"):
            self.code = QTextBrowser()
            self.code.setHtml(self._code_html(item))
            lines = len(item["removed"]) + len(item.get("kept", [])) + 6
            self.code.setFixedHeight(min(280, 30 + 17 * lines))
            self.code.setVisible(start_open)
            btn = QPushButton("Hide code" if start_open else "Show the code being removed")
            btn.setFlat(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet("text-align:left; color:#2f6fde; padding:0; border:none")

            def toggle():
                vis = not self.code.isVisible()
                self.code.setVisible(vis)
                btn.setText("Hide code" if vis else "Show the code being removed")
            btn.clicked.connect(toggle)
            col.addWidget(btn, 0, Qt.AlignLeft)
            col.addWidget(self.code)

    @staticmethod
    def _code_html(item):
        e = html.escape
        out = [f"<div style='font-family:Consolas,\"Cascadia Mono\",Menlo,monospace; font-size:11px'>",
               f"<b style='color:{DANGER}'>{'File contents (all removed):' if item['action'] == 'delete' else 'Removed lines:'}</b><br>"]
        out += [f"<span style='color:{DANGER}'>− {e(l)}</span><br>" for l in item["removed"]]
        if item.get("more_removed"):
            out.append(f"<span style='color:{MUTED}'>… and {item['more_removed']} more lines</span><br>")
        if item.get("kept"):
            out.append(f"<br><b style='color:{SAFE}'>Replaced with (your code, kept):</b><br>")
            out += [f"<span style='color:{SAFE}'>+ {e(l)}</span><br>" for l in item["kept"]]
            if item.get("more_kept"):
                out.append(f"<span style='color:{MUTED}'>… and {item['more_kept']} more lines</span><br>")
        elif item["action"] == "clean":
            out.append(f"<br><span style='color:{MUTED}'>Those lines are removed with nothing in their place.</span><br>")
        out.append(f"<br><span style='color:{MUTED}'>RepoGuard only shows this code as text. It never runs it.</span></div>")
        return "".join(out)


def _scroll(inner):
    sc = QScrollArea()
    sc.setWidgetResizable(True)
    sc.setFrameShape(QFrame.NoFrame)
    sc.setWidget(inner)
    return sc


def _header(lay, title, *lines):
    lay.addWidget(label(title, size=20, bold=True))
    for l in lines:
        lay.addWidget(label(l, color=MUTED))


MODES = [("mac", "This PC only", "Cleans your files and local branches. GitHub is not touched."),
         ("github", "This PC and GitHub", "Also pushes one \"Remove malware (RepoGuard)\" commit to each infected GitHub branch. "
          "A normal push, no force-push, so no history is rewritten. Teammates will see that commit."),
         ("permanent", "Permanently", "Also deletes infected tags and purges the infected commits from this PC's git history. "
          "This can't be undone.")]


class CleanReviewDialog(QDialog):
    """Remove Malware on this PC. Returns the chosen mode via .mode after exec() == Accepted."""

    def __init__(self, plan, parent=None, open_first=False):
        super().__init__(parent)
        self.plan, self.mode = plan, "mac"
        self.setWindowTitle("Review before removing")
        self.resize(860, 720)
        lay = QVBoxLayout(self)
        _header(lay, "Review before removing", summary_line(plan["items"]),
                "Nothing has been changed yet. Every original is backed up first, read-only.")
        inner = QWidget()
        body = QVBoxLayout(inner)
        first_clean = next((i for i in plan["items"] if i["action"] == "clean"), None)
        repos = sorted({i["repo"] for i in plan["items"]} | {r["repo"] for r in plan["refs"]})
        self.ref_labels = []
        for repo in repos:
            body.addWidget(label("📁 " + short(repo), size=14, bold=True))
            for it in [i for i in plan["items"] if i["repo"] == repo]:
                body.addWidget(ItemRow(it, start_open=open_first and it is first_clean))
            refs = [r for r in plan["refs"] if r["repo"] == repo]
            if refs:
                body.addWidget(label("Git branches", bold=True))
                for r in refs:
                    body.addWidget(label(r["ref"], bold=True, mono=True))
                    l = label("", color=None)
                    self.ref_labels.append((r, l))
                    body.addWidget(l)
        notes = plan.get("manual", []) + plan.get("skipped", [])
        if notes:
            body.addWidget(label("Not touched", size=14, bold=True))
            for n in notes:
                body.addWidget(label(f"• {short(n['path'])}: {n['why']}", color=MUTED))
        body.addStretch(1)
        lay.addWidget(_scroll(inner), 1)

        modes = QHBoxLayout()
        self.group = QButtonGroup(self)
        for i, (key, name, _) in enumerate(MODES):
            rb = QRadioButton(name)
            rb.setChecked(i == 0)
            rb.toggled.connect(lambda on, k=key: on and self._set_mode(k))
            self.group.addButton(rb)
            modes.addWidget(rb)
        modes.addStretch(1)
        lay.addLayout(modes)
        self.mode_text = label(MODES[0][2], color=MUTED)
        lay.addWidget(self.mode_text)
        btns = QHBoxLayout()
        btns.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        self.go = QPushButton("Remove Malware")
        self.go.setStyleSheet(f"background:{DANGER}; color:white; padding:6px 16px; border-radius:6px; font-weight:600")
        self.go.clicked.connect(self.accept)
        self.go.setEnabled(any(i["action"] != "manual" for i in plan["items"]) or bool(plan["refs"]))
        btns.addWidget(cancel)
        btns.addWidget(self.go)
        lay.addLayout(btns)
        self._set_mode("mac")

    def _set_mode(self, key):
        self.mode = key
        desc = next(d for k, _, d in MODES if k == key)
        self.mode_text.setText(desc)
        self.mode_text.setStyleSheet(f"color:{DANGER if key == 'permanent' else MUTED}")
        self.go.setText("Remove Permanently" if key == "permanent" else "Remove Malware")
        for r, l in self.ref_labels:
            l.setText(self._ref_action(r))

    def _ref_action(self, r):
        if r["kind"] == "github":
            return ("Download it from GitHub again. If GitHub still has the malware, delete this local copy (GitHub keeps its own)."
                    if self.mode == "mac" else
                    "Download it from GitHub again. If it's still infected, push a \"Remove malware (RepoGuard)\" commit to GitHub.")
        if r["kind"] == "branch":
            s = ("Move it back to the clean GitHub version. The only differences are malware." if r.get("plan") == "move"
                 else "Add a \"Remove malware (RepoGuard)\" commit on top. Your own work is kept.")
            if r.get("checked_out"):
                s += " Your open files update too. If you have unsaved edits in the same files, it stops and asks you to commit them first."
            return s
        return "Delete this tag." if self.mode == "permanent" else "Kept as it is. Only Permanently deletes it."


class GitHubReviewDialog(QDialog):
    """Fix on GitHub. After exec() == Accepted, .approved holds the ticked branch ids."""

    def __init__(self, plan, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Review before fixing on GitHub")
        self.resize(860, 720)
        lay = QVBoxLayout(self)
        items = [i for b in plan["branches"] for i in b["items"]]
        _header(lay, "Review before fixing on GitHub", summary_line(items),
                "Each ticked branch gets one \"Remove malware (RepoGuard)\" commit on top. It's a normal push, not a "
                "force-push. Teammates will see that commit. Nothing has been changed yet.")
        inner = QWidget()
        body = QVBoxLayout(inner)
        self.boxes = []
        for b in plan["branches"]:
            box = QCheckBox(f"{b['repo']}   {b['branch']}")
            box.setStyleSheet("font-weight:600; font-size:14px")
            fixable = not b["error"] and any(i["action"] != "manual" for i in b["items"])
            box.setChecked(fixable)
            box.setEnabled(fixable)
            box.toggled.connect(self._count)
            self.boxes.append((b["id"], box))
            body.addWidget(box)
            if b["error"]:
                body.addWidget(label(b["error"], color=CAUTION))
            for it in b["items"]:
                row = ItemRow(it)
                row.setContentsMargins(24, 0, 0, 0)
                body.addWidget(row)
        body.addStretch(1)
        lay.addWidget(_scroll(inner), 1)
        btns = QHBoxLayout()
        btns.addWidget(label("A branch pushed to after this review is skipped, so only what you saw here is changed.", size=11, color=MUTED))
        btns.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        self.go = QPushButton()
        self.go.setStyleSheet(f"background:{DANGER}; color:white; padding:6px 16px; border-radius:6px; font-weight:600")
        self.go.clicked.connect(self.accept)
        btns.addWidget(cancel)
        btns.addWidget(self.go)
        lay.addLayout(btns)
        self._count()

    def _count(self):
        n = len(self.approved)
        self.go.setText(f"Fix {n} Branch{'es' if n != 1 else ''} on GitHub")
        self.go.setEnabled(n > 0)

    @property
    def approved(self):
        return [i for i, b in self.boxes if b.isChecked()]
