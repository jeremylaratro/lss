"""
Unit tests for ids_suite.models.eve_reader module
"""

import os
import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open, MagicMock
from ids_suite.models.eve_reader import EVEFileReader


class TestEVEFileReader:
    """Test suite for EVEFileReader class"""

    def test_initialization_default_path(self):
        """Test reader initializes with default path"""
        reader = EVEFileReader()

        assert reader.base_path == "/var/log/suricata"
        assert reader.primary_file == "/var/log/suricata/eve.json"
        assert reader.current_file is None
        assert reader.current_inode is None
        assert reader.position == 0

    def test_initialization_custom_path(self):
        """Test reader initializes with custom path"""
        custom_path = "/custom/path/suricata"
        reader = EVEFileReader(base_path=custom_path)

        assert reader.base_path == custom_path
        assert reader.primary_file == f"{custom_path}/eve.json"
        assert reader.position == 0

    def test_get_inode_existing_file(self, mock_eve_file):
        """Test _get_inode returns inode for existing file"""
        reader = EVEFileReader()

        inode = reader._get_inode(mock_eve_file)

        assert inode is not None
        assert isinstance(inode, int)
        assert inode > 0

    def test_get_inode_nonexistent_file(self):
        """Test _get_inode returns None for nonexistent file"""
        reader = EVEFileReader()

        inode = reader._get_inode("/nonexistent/path/file.json")

        assert inode is None

    def test_detect_rotation_no_current_file(self):
        """Test rotation detected when no current file set"""
        reader = EVEFileReader()

        assert reader._detect_rotation() is True

    def test_detect_rotation_file_deleted(self, temp_dir):
        """Test rotation detected when current file deleted"""
        reader = EVEFileReader(base_path=temp_dir)
        reader.current_file = os.path.join(temp_dir, "deleted.json")

        # File doesn't exist
        assert reader._detect_rotation() is True

    def test_detect_rotation_inode_changed(self, temp_dir):
        """Test rotation detected when inode changes"""
        # Create initial file
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"event": "test"}\n')

        reader = EVEFileReader(base_path=temp_dir)
        reader.current_file = str(eve_file)
        reader.current_inode = reader._get_inode(str(eve_file))

        # Delete and recreate (new inode)
        eve_file.unlink()
        eve_file.write_text('{"event": "new"}\n')

        assert reader._detect_rotation() is True

    def test_detect_rotation_file_truncated(self, temp_dir):
        """Test rotation detected when file is truncated"""
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"event": "test"}\n' * 100)

        reader = EVEFileReader(base_path=temp_dir)
        reader.current_file = str(eve_file)
        reader.current_inode = reader._get_inode(str(eve_file))
        reader.position = 1000  # Position beyond current size

        # Truncate file
        eve_file.write_text('{"event": "small"}\n')

        assert reader._detect_rotation() is True

    def test_detect_rotation_no_rotation(self, temp_dir):
        """Test no rotation detected when file unchanged"""
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"event": "test"}\n')

        reader = EVEFileReader(base_path=temp_dir)
        reader.current_file = str(eve_file)
        reader.current_inode = reader._get_inode(str(eve_file))
        reader.position = 10

        assert reader._detect_rotation() is False

    def test_find_active_file_primary_exists(self, temp_dir):
        """Test finding primary eve.json file"""
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"event": "test"}\n')

        reader = EVEFileReader(base_path=temp_dir)
        active_file = reader._find_active_file()

        assert active_file == str(eve_file)

    def test_find_active_file_primary_empty(self, temp_dir):
        """Test finding active file when primary is empty"""
        # Create empty primary file
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('')

        # Create rotated file with content
        rotated = Path(temp_dir) / "eve.json-20260121"
        rotated.write_text('{"event": "rotated"}\n')

        reader = EVEFileReader(base_path=temp_dir)
        active_file = reader._find_active_file()

        # Should find the rotated file with content
        assert active_file == str(rotated)

    def test_find_active_file_multiple_rotated(self, temp_dir):
        """Test finding most recent rotated file"""
        # Create multiple rotated files
        old_file = Path(temp_dir) / "eve.json-20260110"
        old_file.write_text('{"event": "old"}\n')

        mid_file = Path(temp_dir) / "eve.json-20260115"
        mid_file.write_text('{"event": "mid"}\n')

        new_file = Path(temp_dir) / "eve.json-20260120"
        new_file.write_text('{"event": "new"}\n')

        # Set different modification times
        import time
        os.utime(str(old_file), (time.time() - 200, time.time() - 200))
        os.utime(str(mid_file), (time.time() - 100, time.time() - 100))
        os.utime(str(new_file), (time.time() - 50, time.time() - 50))

        reader = EVEFileReader(base_path=temp_dir)
        active_file = reader._find_active_file()

        # Should find the most recently modified file
        assert active_file == str(new_file)

    def test_find_active_file_fallback_to_primary(self, temp_dir):
        """Test fallback to primary file when nothing found"""
        reader = EVEFileReader(base_path=temp_dir)
        active_file = reader._find_active_file()

        # Should return primary file path even if it doesn't exist
        assert active_file == os.path.join(temp_dir, "eve.json")

    def test_read_from_position_basic(self, temp_dir):
        """Test reading lines from file at position"""
        eve_file = Path(temp_dir) / "eve.json"
        content = '{"line": 1}\n{"line": 2}\n{"line": 3}\n'
        eve_file.write_text(content)

        reader = EVEFileReader(base_path=temp_dir)
        lines = reader._read_from_position(str(eve_file), 0)

        assert len(lines) == 3
        assert lines[0] == '{"line": 1}'
        assert lines[1] == '{"line": 2}'
        assert lines[2] == '{"line": 3}'

    def test_read_from_position_with_offset(self, temp_dir):
        """Test reading from middle of file"""
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"line": 1}\n{"line": 2}\n{"line": 3}\n')

        reader = EVEFileReader(base_path=temp_dir)

        # Read first line to set position
        reader.current_file = str(eve_file)
        first_line_len = len('{"line": 1}\n')

        # Read from position after first line
        lines = reader._read_from_position(str(eve_file), first_line_len)

        assert len(lines) == 2
        assert lines[0] == '{"line": 2}'
        assert lines[1] == '{"line": 3}'

    def test_read_from_position_max_lines(self, temp_dir):
        """Test reading limited number of lines"""
        eve_file = Path(temp_dir) / "eve.json"
        content = '\n'.join([f'{{"line": {i}}}' for i in range(1, 11)]) + '\n'
        eve_file.write_text(content)

        reader = EVEFileReader(base_path=temp_dir)
        lines = reader._read_from_position(str(eve_file), 0, max_lines=5)

        assert len(lines) == 5
        assert lines[0] == '{"line": 1}'
        assert lines[4] == '{"line": 5}'

    def test_read_from_position_empty_lines(self, temp_dir):
        """Test that empty lines are skipped"""
        eve_file = Path(temp_dir) / "eve.json"
        content = '{"line": 1}\n\n\n{"line": 2}\n\n{"line": 3}\n'
        eve_file.write_text(content)

        reader = EVEFileReader(base_path=temp_dir)
        lines = reader._read_from_position(str(eve_file), 0)

        assert len(lines) == 3
        assert lines[0] == '{"line": 1}'
        assert lines[1] == '{"line": 2}'
        assert lines[2] == '{"line": 3}'

    def test_read_from_position_updates_position(self, temp_dir):
        """Test that position is updated after reading"""
        eve_file = Path(temp_dir) / "eve.json"
        content = '{"line": 1}\n{"line": 2}\n'
        eve_file.write_text(content)

        reader = EVEFileReader(base_path=temp_dir)
        initial_position = reader.position

        lines = reader._read_from_position(str(eve_file), 0)

        assert reader.position > initial_position
        assert reader.position == len(content)

    def test_read_from_position_nonexistent_file(self):
        """Test reading from nonexistent file returns empty list"""
        reader = EVEFileReader()
        lines = reader._read_from_position("/nonexistent/file.json", 0)

        assert lines == []

    def test_read_new_lines_basic(self, mock_eve_file):
        """Test reading new lines from file"""
        reader = EVEFileReader(base_path=os.path.dirname(mock_eve_file))
        reader.primary_file = mock_eve_file

        lines = reader.read_new_lines()

        assert len(lines) > 0
        assert all(isinstance(line, str) for line in lines)

    def test_read_new_lines_incremental(self, temp_dir):
        """Test incremental reading of new lines"""
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"line": 1}\n{"line": 2}\n')

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        # First read
        lines1 = reader.read_new_lines()
        assert len(lines1) == 2

        # Append new lines
        with open(eve_file, 'a') as f:
            f.write('{"line": 3}\n{"line": 4}\n')

        # Second read should only get new lines
        lines2 = reader.read_new_lines()
        assert len(lines2) == 2
        assert lines2[0] == '{"line": 3}'
        assert lines2[1] == '{"line": 4}'

    def test_read_new_lines_with_rotation(self, temp_dir):
        """Test reading new lines handles rotation"""
        old_file = Path(temp_dir) / "eve.json"
        old_file.write_text('{"file": "old", "line": 1}\n{"file": "old", "line": 2}\n')

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(old_file)

        # Initial read
        lines1 = reader.read_new_lines()
        assert len(lines1) == 2

        # Simulate rotation: rename old file, create new one
        rotated_file = Path(temp_dir) / "eve.json-20260121"
        old_file.rename(rotated_file)

        new_file = Path(temp_dir) / "eve.json"
        new_file.write_text('{"file": "new", "line": 1}\n')

        # Read should detect rotation and read from new file
        lines2 = reader.read_new_lines()

        # Should have read from new file
        assert any('new' in line for line in lines2)

    def test_read_new_lines_max_lines_limit(self, temp_dir):
        """Test max_lines parameter limits output"""
        eve_file = Path(temp_dir) / "eve.json"
        content = '\n'.join([f'{{"line": {i}}}' for i in range(1, 101)]) + '\n'
        eve_file.write_text(content)

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        lines = reader.read_new_lines(max_lines=10)

        assert len(lines) <= 10

    @patch('subprocess.run')
    def test_initial_load_basic(self, mock_run, temp_dir):
        """Test initial load using tail command"""
        eve_file = Path(temp_dir) / "eve.json"
        content = '\n'.join([f'{{"line": {i}}}' for i in range(1, 21)]) + '\n'
        eve_file.write_text(content)

        # Mock subprocess.run to return content
        mock_result = Mock()
        mock_result.stdout = content
        mock_run.return_value = mock_result

        reader = EVEFileReader(base_path=temp_dir)
        lines = reader.initial_load(num_lines=10)

        assert len(lines) > 0
        assert reader.position == os.path.getsize(str(eve_file))

    @patch('subprocess.run')
    def test_initial_load_sets_position(self, mock_run, temp_dir):
        """Test initial load sets position to end of file"""
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"line": 1}\n{"line": 2}\n')

        mock_result = Mock()
        mock_result.stdout = '{"line": 1}\n{"line": 2}\n'
        mock_run.return_value = mock_result

        reader = EVEFileReader(base_path=temp_dir)
        reader.initial_load()

        assert reader.position == os.path.getsize(str(eve_file))
        assert reader.current_file == str(eve_file)
        assert reader.current_inode is not None

    @patch('subprocess.run')
    def test_initial_load_empty_file(self, mock_run, temp_dir):
        """Test initial load with empty file"""
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('')

        mock_result = Mock()
        mock_result.stdout = ''
        mock_run.return_value = mock_result

        reader = EVEFileReader(base_path=temp_dir)
        lines = reader.initial_load()

        assert lines == []

    def test_initial_load_nonexistent_file(self):
        """Test initial load with nonexistent file"""
        reader = EVEFileReader(base_path="/nonexistent/path")
        lines = reader.initial_load()

        assert lines == []

    def test_reset(self, temp_dir):
        """Test reset clears reader state"""
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"line": 1}\n')

        reader = EVEFileReader(base_path=temp_dir)
        reader.current_file = str(eve_file)
        reader.current_inode = 12345
        reader.position = 100

        reader.reset()

        assert reader.current_file is None
        assert reader.current_inode is None
        assert reader.position == 0

    def test_json_line_parsing_valid(self, temp_dir):
        """Test that returned lines are valid JSON strings"""
        eve_file = Path(temp_dir) / "eve.json"
        events = [
            {"event_type": "alert", "severity": 1},
            {"event_type": "flow", "pkts": 100},
            {"event_type": "dns", "query": "example.com"}
        ]

        content = '\n'.join([json.dumps(e) for e in events]) + '\n'
        eve_file.write_text(content)

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        lines = reader.read_new_lines()

        # All lines should be parseable JSON
        for line in lines:
            parsed = json.loads(line)
            assert isinstance(parsed, dict)

    def test_json_line_parsing_invalid(self, temp_dir):
        """Test handling of invalid JSON lines"""
        eve_file = Path(temp_dir) / "eve.json"
        content = '{"valid": "json"}\n{invalid json}\n{"another": "valid"}\n'
        eve_file.write_text(content)

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        lines = reader.read_new_lines()

        # Should still read all lines (parser doesn't validate JSON)
        assert len(lines) == 3

        # First and last should parse correctly
        assert json.loads(lines[0]) == {"valid": "json"}
        assert json.loads(lines[2]) == {"another": "valid"}

        # Middle line should raise error when parsed
        with pytest.raises(json.JSONDecodeError):
            json.loads(lines[1])

    def test_permission_error_handling(self, temp_dir):
        """Test handling of permission errors"""
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"line": 1}\n')

        reader = EVEFileReader(base_path=temp_dir)

        # Mock open to raise PermissionError
        with patch('builtins.open', side_effect=PermissionError):
            lines = reader._read_from_position(str(eve_file), 0)
            assert lines == []

    def test_concurrent_rotation_handling(self, temp_dir):
        """Test handling rotation that occurs during read"""
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"line": 1}\n{"line": 2}\n')

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        # First read to establish state
        lines1 = reader.read_new_lines()
        assert len(lines1) == 2

        # Simulate log rotation
        old_inode = reader.current_inode
        eve_file.unlink()
        eve_file.write_text('{"line": 3}\n')

        # Should detect rotation and reset
        lines2 = reader.read_new_lines()
        assert reader.current_inode != old_inode
        assert reader.position >= 0
