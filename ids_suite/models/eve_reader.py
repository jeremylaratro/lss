"""
EVE File Reader for incremental reading of Suricata EVE JSON logs
"""

import os
import subprocess
from typing import List, Optional


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
                        pass

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
            except PermissionError:
                # Fall back to tail command for permission issues
                pass

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
        except (IOError, OSError):
            pass
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
            result = subprocess.run(
                f"tail -{num_lines} '{self.current_file}'",
                shell=True, capture_output=True, text=True
            )
            lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]

            # Set position to end of file for future incremental reads
            self.position = os.path.getsize(self.current_file)
        except Exception:
            pass

        return lines

    def reset(self) -> None:
        """Reset reader state"""
        self.current_file = None
        self.current_inode = None
        self.position = 0
