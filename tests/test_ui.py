"""The window, every page and both review dialogs build (offscreen) from real core output."""
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from conftest import core, infect, git  # noqa: E402

RULES = os.path.join(os.path.dirname(__file__), "..", "repoguard", "core", "rules.json")


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_window_and_review_dialogs(app, tmp_path, remote):
    from repoguard.app.model import Model
    from repoguard.app.review import CleanReviewDialog, GitHubReviewDialog
    from repoguard.app.ui import MainWindow

    from repoguard import paths
    paths.support_dir()
    watch = tmp_path / "watch"
    infect(watch / "loose")
    rc, scan, err = core("engine", "full", "--watch", str(watch), "--state", os.path.join(os.environ["REPOGUARD_SUPPORT"], "state.json"),
                         "--rules", RULES)
    assert scan["active"], err
    m = Model()
    m.settings["watch_dirs"] = [str(watch)]
    m._apply_scan(scan, notify=False)
    m.gh["findings"] = [{"repo": "acme/app", "branch": "main", "sha": "a" * 40, "files": ["init"], "labels": ["Known malware code"],
                         "time": "now", "existing": False}]
    win = MainWindow(m)
    for i, page in enumerate(win.pages):
        win.nav.setCurrentRow(i)
        app.processEvents()
        assert page.body.count() > 1, page.title
    assert win.nav.item(1).text().startswith("Threats  (")

    rc, plan, err = core("cleaner", "--state", os.path.join(os.environ["REPOGUARD_SUPPORT"], "state.json"), "--rules", RULES, "--preview")
    dlg = CleanReviewDialog(plan, win, open_first=True)
    assert dlg.go.isEnabled() and dlg.mode == "mac"
    dlg.group.buttons()[2].setChecked(True)
    assert dlg.mode == "permanent" and dlg.go.text() == "Remove Permanently"

    item = plan["items"][0]
    gplan = {"branches": [{"id": "acme/app|main|" + "a" * 40, "repo": "acme/app", "branch": "main", "items": [item], "error": ""},
                          {"id": "acme/app|locked|" + "b" * 40, "repo": "acme/app", "branch": "locked", "items": [], "error": "branch is protected"}]}
    g = GitHubReviewDialog(gplan, win)
    assert g.approved == ["acme/app|main|" + "a" * 40]
    g.boxes[0][1].setChecked(False)
    assert g.approved == [] and not g.go.isEnabled()
