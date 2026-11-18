"""Entry point for the standalone executable."""

import sys

from printer_goblin.cli import main


if __name__ == "__main__":
    if sys.platform == "win32" and len(sys.argv) == 1:
        print("Close this window to stop Printer Goblin.", flush=True)
    raise SystemExit(main())
