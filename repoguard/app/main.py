"""Starts the RepoGuard app: one instance, a tray icon, and the window (hidden with --background)."""
import json, os, sys

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from PySide6.QtCore import QTimer
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import QApplication

from repoguard import paths
from repoguard.app.model import Model, log
from repoguard.app.ui import APP_NAME, MainWindow, Tray, shield_icon, wire_alerts

SERVER = "RepoGuard-" + (os.environ.get("USERNAME") or os.environ.get("USER") or "user")


def already_running():
    s = QLocalSocket()
    s.connectToServer(SERVER)
    if s.waitForConnected(300):
        s.write(b"show")
        s.flush()
        s.waitForBytesWritten(300)
        return True
    return False


def snapshots(app, out_dir, plan_file=None):
    """Renders every page (and the review dialog) to PNG files, for checking the design in CI."""
    from repoguard.app.review import CleanReviewDialog
    os.makedirs(out_dir, exist_ok=True)
    m = Model()
    win = MainWindow(m)
    win.resize(1080, 700)
    win.show()
    for i, page in enumerate(win.pages):
        win.nav.setCurrentRow(i)
        app.processEvents()
        win.grab().save(os.path.join(out_dir, f"{i}-{page.title.replace(' ', '-').lower()}.png"))
    if plan_file:
        dlg = CleanReviewDialog(json.load(open(plan_file, encoding="utf8")), win, open_first=True)
        dlg.show()
        app.processEvents()
        dlg.grab().save(os.path.join(out_dir, "review.png"))
        dlg.close()
    win.quitting = True
    win.close()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(shield_icon())
    if "--snapshot" in sys.argv:
        i = sys.argv.index("--snapshot")
        plan = sys.argv[sys.argv.index("--plan") + 1] if "--plan" in sys.argv else None
        snapshots(app, sys.argv[i + 1], plan)
        return 0
    if already_running():
        return 0
    server = QLocalServer()
    QLocalServer.removeServer(SERVER)
    server.listen(SERVER)
    model = Model()
    win = MainWindow(model)
    tray = Tray(app, win, model)
    tray.show()
    wire_alerts(win, model, tray)

    def on_conn():
        c = server.nextPendingConnection()
        c.readyRead.connect(lambda: tray.open())
    server.newConnection.connect(on_conn)
    if "--background" not in sys.argv:
        win.show()
    log(f"APP started (data in {paths.support_dir()})")
    QTimer.singleShot(0, model.start)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
