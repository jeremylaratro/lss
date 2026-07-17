#!/usr/bin/env python3
"""
Security Suite Control Panel v2.9.1
Entry point for the modular IDS/AV control panel

Usage:
    python idsgui.py

Or make executable:
    chmod +x idsgui.py
    ./idsgui.py
"""

import sys
import logging
import tkinter as tk

# Add the package to path if running directly
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from ids_suite.ui.main_window import SecurityControlPanel


def _setup_logging():
    """Configure application logging.

    The app previously had no logging and swallowed errors into empty views;
    logging to both a rotating file and stderr makes failures diagnosable.
    """
    log_dir = Path.home() / ".local" / "share" / "security-suite"
    handlers = [logging.StreamHandler()]
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_dir / "security-suite.log"))
    except OSError:
        # Fall back to stderr-only if the log dir isn't writable
        pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )


def main():
    """Main entry point for the Security Suite Control Panel"""
    _setup_logging()
    root = tk.Tk()
    app = SecurityControlPanel(root)
    root.mainloop()


if __name__ == "__main__":
    main()
