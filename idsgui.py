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
import tkinter as tk

# Add the package to path if running directly
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from ids_suite.ui.main_window import SecurityControlPanel


def main():
    """Main entry point for the Security Suite Control Panel"""
    root = tk.Tk()
    app = SecurityControlPanel(root)
    root.mainloop()


if __name__ == "__main__":
    main()
