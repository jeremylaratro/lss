"""
EVE File Reader for incremental reading of Suricata EVE JSON logs
"""

import os
import subprocess
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


class EVEFileReader:
    """Incremental EVE JSON file reader with rotation detection.

    Reads new lines from Suricata's eve.json file efficiently by tracking
    file position and detecting log rotation via inode changes.
    """

    def __init__(self, base_path: str = "/var/log/suricata"):
        self.base_path = base_path
        self.primary_file = os.path.join(base_path, "eve.json")
        self.current_file: Optional[str] = None
        self.current_inode: Optional[int] = None
        self.position: int = 0
        self.last_error: Optional[str] = None

    def _get_inode(self, filepath: str) -> Optional[int]:
        """Get inode of file for rotation detection"""
        try:
            return os.stat(filepath).st_ino
        except OSError:
            return None

    def _detect_rotation(self) -> bool:
        """Check if log file has been rotated"""
        if not self.current_file or not os.path.exists(self.current_file):
            return True

        new_inode = self._get_inode(self.current_file)
        if new_inode != self.current_inode:
            return True

        # Check if file was truncated (size < position)
        try:
            if os.path.getsize(self.current_file) < self.position:
                return True
        except OSError:
            return True

        return False

    def _find_active_file(self) -> str:
        """Find the currently active EVE log file"""
        # Check primary file first
        if os.path.exists(self.primary_file):
            try:
                if os.path.getsize(self.primary_file) > 0:
                    return self.primary_file
            except OSError:
                pass

        # Check for rotated files
        try:
            rotated = []
            for f in os.listdir(self.base_path):
                if f.startswith("eve.json-"):
                    fpath = os.path.join(self.base_path, f)
                    try:
                        mtime = os.path.getmtime(fpath)
                        if os.path.getsize(fpath) > 0:
                            rotated.append((fpath, mtime))
                    except OSError:
                        continue
            if rotated:
                rotated.sort(key=lambda x: x[1], reverse=True)
                return rotated[0][0]
        except OSError:
            pass

        return self.primary_file

    def _pkexec_tail(self, path: str, max_lines: int) -> List[str]:
        """Attempt a privileged read of the tail of `path` via pkexec.

        Used as a fallback when direct file access raises PermissionError.
        Never raises; logs and records self.last_error on any failure.
        """
        try:
            result = subprocess.run(
                ["pkexec", "tail", "-n", str(max_lines), path],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                return [l.strip() for l in result.stdout.split('\n') if l.strip()]

            logger.warning(
                "pkexec tail fallback failed for %s (rc=%s): %s",
                path, result.returncode, (result.stderr or "").strip()
            )
        except FileNotFoundError:
            logger.warning("pkexec not found; cannot escalate read of %s", path)
        except subprocess.TimeoutExpired:
            logger.warning("pkexec tail timed out reading %s", path)
        except Exception:
            logger.warning("pkexec tail fallback raised for %s", path, exc_info=True)

        self.last_error = (
            f"Permission denied reading {path}; add your user to the "
            "'suricata' group"
        )
        return []

    def read_new_lines(self, max_lines: int = 5000) -> List[str]:
        """Read new lines since last read, handling rotation.

        Returns list of new JSON line strings.
        """
        lines: List[str] = []

        # Check for rotation
        if self._detect_rotation():
            new_file = self._find_active_file()

            # If file changed, try to read remainder of old file first
            if self.current_file and self.current_file != new_file:
                if os.path.exists(self.current_file):
                    try:
                        remaining = self._read_from_position(
                            self.current_file, self.position, max_lines
                        )
                        lines.extend(remaining)
                    except Exception:
                        logger.warning(
                            "Failed reading remainder of rotated file %s",
                            self.current_file, exc_info=True
                        )

            # Switch to new file
            self.current_file = new_file
            self.current_inode = self._get_inode(new_file)
            self.position = 0

        # Read from current file
        if self.current_file and os.path.exists(self.current_file):
            try:
                remaining_max = max_lines - len(lines) if max_lines else None
                new_lines = self._read_from_position(
                    self.current_file, self.position, remaining_max
                )
                lines.extend(new_lines)
                self.last_error = None
            except PermissionError:
                # Fall back to a privileged tail read for permission issues
                logger.warning(
                    "Permission denied reading %s; attempting pkexec tail fallback",
                    self.current_file
                )
                fallback_lines = self._pkexec_tail(
                    self.current_file, max_lines if max_lines else 5000
                )
                if fallback_lines:
                    self.last_error = None
                lines.extend(fallback_lines)

        return lines

    def _read_from_position(
        self, filepath: str, position: int, max_lines: Optional[int] = None
    ) -> List[str]:
        """Read lines from file starting at position"""
        lines: List[str] = []
        try:
            with open(filepath, 'r') as f:
                f.seek(position)
                count = 0
                for line in f:
                    line = line.strip()
                    if line:
                        lines.append(line)
                        count += 1
                        if max_lines and count >= max_lines:
                            break
                self.position = f.tell()
        except PermissionError:
            # Log and record the error, then re-raise so callers (e.g.
            # read_new_lines) can attempt a privileged fallback read.
            logger.warning(
                "Permission denied reading %s at position %s",
                filepath, position, exc_info=True
            )
            self.last_error = (
                f"Permission denied reading {filepath}; add your user to the "
                "'suricata' group"
            )
            raise
        except (IOError, OSError):
            logger.warning(
                "I/O error reading %s at position %s", filepath, position,
                exc_info=True
            )
            self.last_error = f"I/O error reading {filepath}"
        return lines

    def initial_load(self, num_lines: int = 10000) -> List[str]:
        """Load initial data from EVE file using tail (for startup).

        Sets position to end of file after load.
        """
        self.current_file = self._find_active_file()
        if not self.current_file or not os.path.exists(self.current_file):
            return []

        self.current_inode = self._get_inode(self.current_file)

        lines: List[str] = []
        try:
            # Use list-based subprocess call (no shell injection risk)
            result = subprocess.run(
                ["tail", f"-{num_lines}", self.current_file],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0 or (
                not result.stdout.strip() and result.stderr.strip()
            ):
                logger.warning(
                    "tail failed loading %s (rc=%s): %s",
                    self.current_file, result.returncode,
                    (result.stderr or "").strip()
                )
                # Permission issue (or similar) — try a privileged tail.
                lines = self._pkexec_tail(self.current_file, num_lines)
                if lines:
                    # Fallback succeeded — clear the error recorded by tail/pkexec
                    self.last_error = None
            else:
                lines = [
                    l.strip() for l in result.stdout.strip().split('\n') if l.strip()
                ]
                self.last_error = None

            # Set position to end of file for future incremental reads
            self.position = os.path.getsize(self.current_file)
        except Exception:
            logger.error(
                "initial_load failed for %s", self.current_file, exc_info=True
            )
            self.last_error = f"Failed to load initial data from {self.current_file}"

        return lines

    def get_last_error(self) -> Optional[str]:
        """Return a short human-readable string describing the last read
        error encountered (permission or I/O), or None if the last read
        succeeded without issue. Callers (e.g. the UI) can poll this to
        surface a message instead of silently showing an empty log view.
        """
        return self.last_error

    def reset(self) -> None:
        """Reset reader state"""
        self.current_file = None
        self.current_inode = None
        self.position = 0
