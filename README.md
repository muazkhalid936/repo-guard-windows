# RepoGuard for Windows

Watches your code folders, your GitHub repos and your PC for the git worm that force-pushes forged
commits with hidden loader code (`init` files, code hidden off-screen in config files, `node init &&`
in npm scripts, VS Code tasks that run when a folder opens, the Ethereum-based Python loader).

The scanning core (`repoguard/core/`) is shared with the macOS app (repo-guard). It reads files and
git objects as data and never runs anything it scans.

## What it does

| | |
|---|---|
| **Threats** | Watches your folders live and scans every branch. **Review & Remove Malware** shows every file it will delete or cut, with the exact code, before anything changes. Originals are backed up. |
| **Git protection** | Global git hooks that cancel any fetch, pull or clone bringing malware *before* your files change. Works in the terminal, VS Code and GitHub Desktop. |
| **GitHub** | Checks every repo you can push to (via `gh auth login`). **Review & Fix on GitHub** pushes one cleanup commit (no force-push) to the branches you tick. |
| **This PC** | Startup folder, registry Run keys, Scheduled Tasks, PowerShell profiles, VS Code settings, git config, scripts in `%TEMP%`, running programs. |

## Install

Download `RepoGuard-Setup-x.y.z.exe` from the latest GitHub Actions run (artifact **RepoGuard-Setup**)
or from Releases. It installs for your user only (no admin). Needs **Git for Windows**; the GitHub watch
needs the **GitHub CLI** (`winget install GitHub.cli`, then `gh auth login`).

The installer isn't code-signed yet, so Windows SmartScreen will warn: choose *More info → Run anyway*.

To clone an infected repo on purpose (to clean it): `set REPOGUARD_ALLOW_FETCH=1` then `git clone ...`.

## Develop

```
python -m venv .venv && .venv\Scripts\pip install -r requirements-dev.txt
.venv\Scripts\python -m pytest tests           # set QT_QPA_PLATFORM=offscreen on CI
.venv\Scripts\python -m repoguard              # run the app from source
pyinstaller RepoGuard.spec                     # dist\RepoGuard\RepoGuard.exe + repoguard-cli.exe
iscc installer\RepoGuard.iss                   # installer\Output\RepoGuard-Setup-*.exe
```

Every push runs the tests on Windows twice (from source, then against the built `.exe`), builds the
installer and saves screenshots of every page as build artifacts.
