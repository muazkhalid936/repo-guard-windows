"""Writes build/RepoGuard.ico from the same shield the app draws (run before PyInstaller)."""
import os, sys
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from PySide6.QtWidgets import QApplication  # noqa: E402
app = QApplication([])
from repoguard.app.ui import shield_icon  # noqa: E402
os.makedirs("build", exist_ok=True)
pm = shield_icon().pixmap(256, 256)
ok = pm.save(os.path.join("build", "RepoGuard.ico"), "ICO")
print("icon written" if ok else "icon skipped (no ICO writer)")
