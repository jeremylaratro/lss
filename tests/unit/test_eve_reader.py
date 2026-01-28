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


class TestEVEReaderBusinessLogic:
    """
    Business logic tests for EVE file reader.

    The EVE reader is CRITICAL for IDS monitoring:
    - Must efficiently tail large log files (can be gigabytes)
    - Must detect log rotation to avoid missing alerts
    - Must handle concurrent file access (Suricata writes while we read)
    - Must recover from errors without crashing the monitoring loop
    """

    def test_incremental_reads_for_efficient_monitoring(self, temp_dir):
        """
        BUSINESS LOGIC: Only read NEW lines to avoid re-processing.

        Without incremental reading, we would:
        - Waste CPU parsing the same alerts repeatedly
        - Show duplicate alerts in the dashboard
        - Miss new alerts while processing old ones
        """
        eve_file = Path(temp_dir) / "eve.json"

        # Simulate large existing log file
        existing_events = [f'{{"alert_id": {i}}}' for i in range(100)]
        eve_file.write_text('\n'.join(existing_events) + '\n')

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        # First read gets existing events
        first_read = reader.read_new_lines()
        assert len(first_read) == 100

        # Append new alerts (as Suricata would do)
        with open(eve_file, 'a') as f:
            f.write('{"alert_id": 100, "new": true}\n')
            f.write('{"alert_id": 101, "new": true}\n')

        # Second read ONLY gets the 2 new alerts
        second_read = reader.read_new_lines()
        assert len(second_read) == 2
        assert '"new": true' in second_read[0]
        assert '"new": true' in second_read[1]

    def test_rotation_detection_prevents_alert_gaps(self, temp_dir):
        """
        BUSINESS LOGIC: Detect log rotation to avoid missing alerts.

        When Suricata rotates logs (e.g., logrotate runs at midnight):
        1. eve.json is renamed to eve.json-YYYYMMDD
        2. A new eve.json is created
        3. Our reader must detect this and switch files

        WITHOUT rotation detection, we'd keep reading the old file
        which stops receiving new alerts - creating a blind spot!
        """
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"pre_rotation": 1}\n{"pre_rotation": 2}\n')

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        # Read pre-rotation alerts
        pre_rotation = reader.read_new_lines()
        assert len(pre_rotation) == 2
        original_inode = reader.current_inode

        # SIMULATE LOG ROTATION
        # Step 1: Rename current file
        rotated_file = Path(temp_dir) / "eve.json-20260127"
        eve_file.rename(rotated_file)

        # Step 2: Create new file
        eve_file.write_text('{"post_rotation": 1}\n')

        # Reader must detect rotation and read from NEW file
        post_rotation = reader.read_new_lines()

        # Verify rotation was detected
        assert reader.current_inode != original_inode, \
            "Must detect inode change indicating rotation"
        assert any('post_rotation' in line for line in post_rotation), \
            "Must read from new file after rotation"

    def test_truncation_detection_handles_log_cleanup(self, temp_dir):
        """
        BUSINESS LOGIC: Detect file truncation (rare but possible).

        Some admins truncate logs with: echo > /var/log/suricata/eve.json
        Our position would be past EOF, causing no new data.

        We must detect this and reset to read from the beginning.
        """
        eve_file = Path(temp_dir) / "eve.json"

        # Create file with substantial content
        original_content = '\n'.join([f'{{"line": {i}}}' for i in range(50)]) + '\n'
        eve_file.write_text(original_content)

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        # Read all content, position now at end
        reader.read_new_lines()
        position_before = reader.position
        assert position_before > 100  # We read substantial content

        # TRUNCATE the file (simulating admin cleanup)
        eve_file.write_text('{"after_truncate": 1}\n')

        # Reader must detect truncation (file size < position)
        assert reader._detect_rotation() is True, \
            "Must detect truncation as a form of rotation"

        # After detection, should read new content
        new_content = reader.read_new_lines()
        assert any('after_truncate' in line for line in new_content), \
            "Must read new content after truncation"

    def test_handles_suricata_continuous_writes(self, temp_dir):
        """
        BUSINESS LOGIC: Handle concurrent writes from Suricata.

        Suricata writes new alerts every time a rule matches.
        High-traffic networks can see 1000s of alerts per second.

        Reader must:
        - Not interfere with Suricata's writes
        - Handle partial line reads gracefully
        - Not lose data between reads
        """
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('')  # Start empty

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        all_lines_read = []

        # Simulate burst of writes followed by reads (like real traffic)
        for batch in range(5):
            # Suricata writes a batch of alerts
            with open(eve_file, 'a') as f:
                for i in range(10):
                    alert_id = batch * 10 + i
                    f.write(f'{{"batch": {batch}, "alert": {alert_id}}}\n')

            # Our app reads at intervals
            new_lines = reader.read_new_lines()
            all_lines_read.extend(new_lines)

        # Must have captured ALL 50 alerts across all batches
        assert len(all_lines_read) == 50, \
            f"Expected 50 alerts, got {len(all_lines_read)} - data was lost!"

        # Verify no duplicates (incremental read working correctly)
        alert_ids = []
        for line in all_lines_read:
            import json
            data = json.loads(line)
            alert_ids.append(data['alert'])
        assert len(alert_ids) == len(set(alert_ids)), \
            "Duplicate alerts detected - incremental read broken"

    def test_graceful_error_recovery(self, temp_dir):
        """
        BUSINESS LOGIC: Recover from errors without crashing.

        The EVE reader runs in a long-lived monitoring loop.
        Temporary errors (disk full, permission issues) must not
        crash the entire IDS monitoring system.
        """
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"before_error": 1}\n')

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        # Read successfully
        lines1 = reader.read_new_lines()
        assert len(lines1) == 1

        # Simulate file disappearing (e.g., disk unmounted briefly)
        eve_file.unlink()

        # Must not crash - return empty list
        lines2 = reader.read_new_lines()
        assert lines2 == [] or isinstance(lines2, list), \
            "Must return empty list on error, not raise exception"

        # File comes back
        eve_file.write_text('{"after_recovery": 1}\n')

        # Must recover and read new data
        lines3 = reader.read_new_lines()
        assert any('after_recovery' in line for line in lines3), \
            "Must recover and continue reading after error resolves"

    def test_max_lines_prevents_memory_exhaustion(self, temp_dir):
        """
        BUSINESS LOGIC: Limit lines per read to prevent memory exhaustion.

        EVE files can be HUGE (gigabytes). Reading the entire file at once
        would crash the application due to memory exhaustion.

        max_lines parameter ensures we process in manageable chunks.
        """
        eve_file = Path(temp_dir) / "eve.json"

        # Create a large-ish file (10,000 lines)
        large_content = '\n'.join([f'{{"line": {i}}}' for i in range(10000)]) + '\n'
        eve_file.write_text(large_content)

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        # Read with reasonable limit
        lines = reader.read_new_lines(max_lines=100)

        # Must respect the limit
        assert len(lines) == 100, \
            f"max_lines not respected: got {len(lines)} instead of 100"

        # Can continue reading the rest
        more_lines = reader.read_new_lines(max_lines=100)
        assert len(more_lines) == 100, \
            "Must be able to continue reading after first batch"

    def test_empty_lines_filtered_not_passed_to_parser(self, temp_dir):
        """
        BUSINESS LOGIC: Filter empty lines before parsing.

        EVE files may contain empty lines due to:
        - Suricata bugs
        - Truncated writes
        - Editor interference

        Passing empty lines to JSON parser causes errors.
        """
        eve_file = Path(temp_dir) / "eve.json"
        # Content with various empty line patterns
        content = '{"line": 1}\n\n   \n\t\n{"line": 2}\n\n{"line": 3}\n'
        eve_file.write_text(content)

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        lines = reader.read_new_lines()

        # Only valid JSON lines returned
        assert len(lines) == 3
        for line in lines:
            assert line.strip(), "Empty/whitespace lines must be filtered"
            # Each should be valid JSON
            import json
            json.loads(line)  # Would raise if invalid

    def test_initial_load_for_startup_context(self, temp_dir):
        """
        BUSINESS LOGIC: initial_load provides historical context on startup.

        When the IDS dashboard starts, users expect to see recent alerts
        immediately, not wait for new ones. initial_load reads the last
        N lines from the file to populate the dashboard.
        """
        eve_file = Path(temp_dir) / "eve.json"

        # Simulate existing log with 1000 historical alerts
        historical = '\n'.join([f'{{"historical": {i}}}' for i in range(1000)]) + '\n'
        eve_file.write_text(historical)

        reader = EVEFileReader(base_path=temp_dir)

        # Load last 100 for immediate display
        with patch('subprocess.run') as mock_run:
            # Mock tail command returning last 100 lines
            last_100 = '\n'.join([f'{{"historical": {i}}}' for i in range(900, 1000)])
            mock_run.return_value = MagicMock(stdout=last_100)

            initial = reader.initial_load(num_lines=100)

            # Should use tail command for efficiency
            mock_run.assert_called_once()
            call_args = str(mock_run.call_args)
            assert 'tail' in call_args, "Must use tail for efficient initial load"
            assert '-100' in call_args, "Must request correct number of lines"

    def test_position_persisted_for_resumable_reads(self, temp_dir):
        """
        BUSINESS LOGIC: Position tracking enables resumable reads.

        If the app restarts, we need to know where we left off.
        Position tracking also ensures we don't re-read old data
        within a single session.
        """
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"line": 1}\n{"line": 2}\n')

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        # Read sets position
        reader.read_new_lines()
        position_after_read = reader.position

        # Position must be at end of what we read
        assert position_after_read == len('{"line": 1}\n{"line": 2}\n'), \
            "Position must track exactly where we stopped"

        # No new data, no position change
        reader.read_new_lines()
        assert reader.position == position_after_read, \
            "Position must not change when no new data"

    def test_finds_most_recent_rotated_file(self, temp_dir):
        """
        BUSINESS LOGIC: Find the most recent rotated file.

        When primary file is empty/missing but rotated files exist,
        we should read from the most recently modified one (has latest alerts).
        """
        import time

        # Create multiple rotated files with different timestamps
        old_rotated = Path(temp_dir) / "eve.json-20260115"
        old_rotated.write_text('{"old": "alerts"}\n')
        os.utime(str(old_rotated), (time.time() - 1000, time.time() - 1000))

        recent_rotated = Path(temp_dir) / "eve.json-20260127"
        recent_rotated.write_text('{"recent": "alerts"}\n')
        os.utime(str(recent_rotated), (time.time() - 10, time.time() - 10))

        # Primary file is empty
        primary = Path(temp_dir) / "eve.json"
        primary.write_text('')

        reader = EVEFileReader(base_path=temp_dir)
        active = reader._find_active_file()

        # Must select the most recently modified file
        assert active == str(recent_rotated), \
            "Must select most recent rotated file, not oldest"

    def test_reset_for_fresh_start(self, temp_dir):
        """
        BUSINESS LOGIC: reset() allows fresh re-scan.

        Users may want to re-scan all alerts (e.g., after filter changes).
        reset() clears all state to allow full re-read.
        """
        eve_file = Path(temp_dir) / "eve.json"
        eve_file.write_text('{"line": 1}\n{"line": 2}\n')

        reader = EVEFileReader(base_path=temp_dir)
        reader.primary_file = str(eve_file)

        # Read all content
        first_read = reader.read_new_lines()
        assert len(first_read) == 2

        # Without reset, nothing new to read
        no_new = reader.read_new_lines()
        assert len(no_new) == 0

        # Reset clears state
        reader.reset()

        # Now can re-read everything
        after_reset = reader.read_new_lines()
        assert len(after_reset) == 2, \
            "After reset, must be able to re-read all content"
