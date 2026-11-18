import sys

if len(sys.argv) > 1 and sys.argv[1] in ("--core", "notify", "protect"):
    from repoguard.cli import main
else:
    from repoguard.app.main import main
sys.exit(main())
