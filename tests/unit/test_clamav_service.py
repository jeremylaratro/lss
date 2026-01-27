"""
Tests for ids_suite/services/clamav_service.py - ClamAV Service manager

Target: 75%+ coverage
"""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock
import subprocess
import os

from ids_suite.services.clamav_service import ClamAVService, ClamAVScanner
from ids_suite.services.privilege_helper import CommandResult
from ids_suite.services.systemd import ServiceResult


class TestClamAVServiceInit:
    """Test ClamAVService initialization"""

    @patch('ids_suite.services.clamav_service.SystemdService')
    def test_init_creates_services(self, mock_systemd):
        """CLAM-001: Init creates three SystemdService instances"""
        service = ClamAVService()
        assert mock_systemd.call_count == 3
        mock_systemd.assert_any_call("clamav-daemon")
        mock_systemd.assert_any_call("clamav-freshclam")
        mock_systemd.assert_any_call("clamav-clamonacc")


class TestClamAVServiceConvertResult:
    """Test result conversion"""

    def test_convert_result_success(self):
        """CLAM-002: Convert CommandResult to ServiceResult - success"""
        service = ClamAVService()
        cmd_result = CommandResult(
            success=True, message="OK", returncode=0,
            stdout="output", stderr=""
        )
        result = service._convert_result(cmd_result)
        assert isinstance(result, ServiceResult)
        assert result.success is True
        assert result.message == "OK"
        assert result.stdout == "output"

    def test_convert_result_failure(self):
        """CLAM-003: Convert CommandResult to ServiceResult - failure"""
        service = ClamAVService()
        cmd_result = CommandResult(
            success=False, message="Failed", returncode=1,
            stdout="", stderr="error"
        )
        result = service._convert_result(cmd_result)
        assert result.success is False
        assert result.stderr == "error"


class TestClamAVServiceStart:
    """Test start() method"""

    @patch('ids_suite.services.clamav_service.run_privileged_batch')
    def test_start_success(self, mock_batch):
        """CLAM-004: Start all services successfully"""
        mock_batch.return_value = CommandResult(
            success=True, message="OK", returncode=0
        )
        service = ClamAVService()
        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        service.start(callback)

        mock_batch.assert_called_once()
        commands = mock_batch.call_args[0][0]
        assert "systemctl start clamav-daemon" in commands
        assert "systemctl start clamav-freshclam" in commands
        assert "systemctl start clamav-clamonacc" in commands
        assert callback_result.success is True
        assert "started" in callback_result.message.lower()

    @patch('ids_suite.services.clamav_service.run_privileged_batch')
    def test_start_failure(self, mock_batch):
        """CLAM-005: Start failure propagates error"""
        mock_batch.return_value = CommandResult(
            success=False, message="Permission denied", returncode=1
        )
        service = ClamAVService()
        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        service.start(callback)

        assert callback_result.success is False
        assert "Permission denied" in callback_result.message

    @patch('ids_suite.services.clamav_service.run_privileged_batch')
    def test_start_no_callback(self, mock_batch):
        """CLAM-006: Start works without callback"""
        mock_batch.return_value = CommandResult(success=True, message="OK", returncode=0)
        service = ClamAVService()
        service.start()  # No callback - should not raise


class TestClamAVServiceStop:
    """Test stop() method"""

    @patch('ids_suite.services.clamav_service.run_privileged_batch')
    def test_stop_success(self, mock_batch):
        """CLAM-007: Stop all services in reverse order"""
        mock_batch.return_value = CommandResult(
            success=True, message="OK", returncode=0
        )
        service = ClamAVService()
        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        service.stop(callback)

        commands = mock_batch.call_args[0][0]
        # Verify reverse order (clamonacc first, then freshclam, then daemon)
        assert commands.index("systemctl stop clamav-clamonacc") < commands.index("systemctl stop clamav-freshclam")
        assert commands.index("systemctl stop clamav-freshclam") < commands.index("systemctl stop clamav-daemon")
        assert callback_result.success is True
        assert "stopped" in callback_result.message.lower()

    @patch('ids_suite.services.clamav_service.run_privileged_batch')
    def test_stop_failure(self, mock_batch):
        """CLAM-008: Stop failure propagates error"""
        mock_batch.return_value = CommandResult(
            success=False, message="Service not found", returncode=1
        )
        service = ClamAVService()
        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        service.stop(callback)

        assert callback_result.success is False


class TestClamAVServiceRestart:
    """Test restart() method"""

    @patch('ids_suite.services.clamav_service.run_privileged_batch')
    def test_restart_success(self, mock_batch):
        """CLAM-009: Restart all services"""
        mock_batch.return_value = CommandResult(
            success=True, message="OK", returncode=0
        )
        service = ClamAVService()
        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        service.restart(callback)

        commands = mock_batch.call_args[0][0]
        assert "systemctl restart clamav-daemon" in commands
        assert "systemctl restart clamav-freshclam" in commands
        assert "systemctl restart clamav-clamonacc" in commands
        assert callback_result.success is True
        assert "restarted" in callback_result.message.lower()


class TestClamAVServiceStatusChecks:
    """Test status check methods"""

    @patch('ids_suite.services.clamav_service.SystemdService')
    def test_is_daemon_running(self, mock_systemd_class):
        """CLAM-010: is_daemon_running delegates to daemon service"""
        mock_daemon = MagicMock()
        mock_daemon.is_active.return_value = True
        mock_systemd_class.side_effect = [mock_daemon, MagicMock(), MagicMock()]

        service = ClamAVService()
        assert service.is_daemon_running() is True
        mock_daemon.is_active.assert_called_once()

    @patch('ids_suite.services.clamav_service.SystemdService')
    def test_is_freshclam_running(self, mock_systemd_class):
        """CLAM-011: is_freshclam_running delegates to freshclam service"""
        mock_freshclam = MagicMock()
        mock_freshclam.is_active.return_value = False
        mock_systemd_class.side_effect = [MagicMock(), mock_freshclam, MagicMock()]

        service = ClamAVService()
        assert service.is_freshclam_running() is False

    @patch('ids_suite.services.clamav_service.SystemdService')
    def test_is_clamonacc_running(self, mock_systemd_class):
        """CLAM-012: is_clamonacc_running delegates to clamonacc service"""
        mock_clamonacc = MagicMock()
        mock_clamonacc.is_active.return_value = True
        mock_systemd_class.side_effect = [MagicMock(), MagicMock(), mock_clamonacc]

        service = ClamAVService()
        assert service.is_clamonacc_running() is True


class TestClamAVServiceUpdateSignatures:
    """Test update_signatures() method"""

    @patch('ids_suite.services.clamav_service.run_privileged_batch')
    def test_update_signatures_success(self, mock_batch):
        """CLAM-013: Update signatures with stop/update/start sequence"""
        mock_batch.return_value = CommandResult(
            success=True, message="OK", returncode=0
        )
        service = ClamAVService()
        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        service.update_signatures(callback)

        commands = mock_batch.call_args[0][0]
        assert "systemctl stop clamav-freshclam" in commands
        assert "freshclam" in commands
        assert "systemctl start clamav-freshclam" in commands
        assert callback_result.success is True
        assert "updated" in callback_result.message.lower()


class TestClamAVServiceGetSignatureCount:
    """Test get_signature_count() method"""

    @patch('subprocess.run')
    def test_get_signature_count_success(self, mock_run):
        """CLAM-014: Get signature count returns number"""
        mock_run.return_value = MagicMock(stdout="12345678\n", returncode=0)
        service = ClamAVService()
        result = service.get_signature_count()
        assert result == "12345678"

    @patch('subprocess.run')
    def test_get_signature_count_empty(self, mock_run):
        """CLAM-015: Empty result returns N/A"""
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        service = ClamAVService()
        result = service.get_signature_count()
        assert result == "N/A"

    @patch('subprocess.run')
    def test_get_signature_count_exception(self, mock_run):
        """CLAM-016: Exception returns N/A"""
        mock_run.side_effect = Exception("error")
        service = ClamAVService()
        result = service.get_signature_count()
        assert result == "N/A"


class TestClamAVServiceGetQuarantineCount:
    """Test get_quarantine_count() method"""

    @patch('os.path.exists')
    @patch('os.listdir')
    @patch('os.path.isfile')
    def test_get_quarantine_count_with_files(self, mock_isfile, mock_listdir, mock_exists):
        """CLAM-017: Count quarantined files"""
        mock_exists.return_value = True
        mock_listdir.return_value = ['file1', 'file2', 'file3']
        mock_isfile.return_value = True

        service = ClamAVService()
        result = service.get_quarantine_count()
        assert result == 3

    @patch('os.path.exists')
    def test_get_quarantine_count_no_dir(self, mock_exists):
        """CLAM-018: No quarantine dir returns 0"""
        mock_exists.return_value = False
        service = ClamAVService()
        result = service.get_quarantine_count()
        assert result == 0

    @patch('os.path.exists')
    @patch('os.listdir')
    def test_get_quarantine_count_exception(self, mock_listdir, mock_exists):
        """CLAM-019: Exception returns 0"""
        mock_exists.return_value = True
        mock_listdir.side_effect = PermissionError()
        service = ClamAVService()
        result = service.get_quarantine_count()
        assert result == 0


class TestClamAVServiceCleanLogs:
    """Test clean_logs() method"""

    @patch('ids_suite.services.clamav_service.run_privileged_command')
    def test_clean_logs_calls_cleanup_script(self, mock_cmd):
        """CLAM-020: clean_logs calls av-cleanup script"""
        mock_cmd.return_value = ServiceResult(success=True, message="OK", returncode=0)
        service = ClamAVService()
        callback_result = None
        def callback(r):
            nonlocal callback_result
            callback_result = r

        service.clean_logs(callback)

        mock_cmd.assert_called_once_with("/usr/local/bin/av-cleanup")
        assert callback_result is not None


class TestClamAVServiceOpenLogs:
    """Test open_logs() method"""

    @patch('subprocess.Popen')
    @patch('os.path.exists')
    def test_open_logs_exists(self, mock_exists, mock_popen):
        """CLAM-021: open_logs opens file manager when dir exists"""
        mock_exists.return_value = True
        service = ClamAVService()
        service.open_logs()
        mock_popen.assert_called_once_with(["xdg-open", "/var/log/clamav"])

    @patch('subprocess.Popen')
    @patch('os.path.exists')
    def test_open_logs_not_exists(self, mock_exists, mock_popen):
        """CLAM-022: open_logs does nothing when dir missing"""
        mock_exists.return_value = False
        service = ClamAVService()
        service.open_logs()
        mock_popen.assert_not_called()


class TestClamAVServiceGetStatusInfo:
    """Test get_status_info() method"""

    @patch.object(ClamAVService, 'is_daemon_running', return_value=True)
    @patch.object(ClamAVService, 'is_freshclam_running', return_value=False)
    @patch.object(ClamAVService, 'is_clamonacc_running', return_value=True)
    @patch.object(ClamAVService, 'get_signature_count', return_value="1000000")
    @patch.object(ClamAVService, 'get_quarantine_count', return_value=5)
    def test_get_status_info(self, *mocks):
        """CLAM-023: get_status_info returns complete status dict"""
        service = ClamAVService()
        info = service.get_status_info()

        assert info['daemon_running'] is True
        assert info['freshclam_running'] is False
        assert info['clamonacc_running'] is True
        assert info['signature_count'] == "1000000"
        assert info['quarantine_count'] == 5


class TestClamAVScannerInit:
    """Test ClamAVScanner initialization"""

    def test_scanner_init(self):
        """CLAM-024: Scanner initializes with defaults"""
        scanner = ClamAVScanner()
        assert scanner.process is None
        assert scanner.cancelled is False


class TestClamAVScannerScan:
    """Test scan() method"""

    @patch('subprocess.Popen')
    def test_scan_basic(self, mock_popen):
        """CLAM-025: Basic scan with default options"""
        mock_process = MagicMock()
        mock_process.stdout.readline.side_effect = ["Scanning...\n", ""]
        mock_process.returncode = 0
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process

        scanner = ClamAVScanner()
        output_lines = []
        def on_output(line):
            output_lines.append(line)
        complete_code = None
        def on_complete(code):
            nonlocal complete_code
            complete_code = code

        scanner.scan("/tmp/test", on_output=on_output, on_complete=on_complete)

        call_args = mock_popen.call_args[0][0]
        assert "clamscan" in call_args
        assert "-r" in call_args  # recursive by default
        assert "/tmp/test" in call_args
        assert "Scanning..." in output_lines
        assert complete_code == 0

    @patch('subprocess.Popen')
    def test_scan_non_recursive(self, mock_popen):
        """CLAM-026: Scan without recursion"""
        mock_process = MagicMock()
        mock_process.stdout.readline.side_effect = [""]
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        scanner = ClamAVScanner()
        scanner.scan("/tmp/test", recursive=False)

        call_args = mock_popen.call_args[0][0]
        assert "-r" not in call_args

    @patch('subprocess.Popen')
    def test_scan_exception(self, mock_popen):
        """CLAM-027: Scan handles exceptions"""
        mock_popen.side_effect = Exception("Command failed")

        scanner = ClamAVScanner()
        output_lines = []
        complete_code = None
        def on_output(line):
            output_lines.append(line)
        def on_complete(code):
            nonlocal complete_code
            complete_code = code

        scanner.scan("/tmp/test", on_output=on_output, on_complete=on_complete)

        assert any("Error" in line for line in output_lines)
        assert complete_code == -1


class TestClamAVScannerCancel:
    """Test cancel() method"""

    def test_cancel_sets_flag(self):
        """CLAM-028: Cancel sets cancelled flag"""
        scanner = ClamAVScanner()
        scanner.cancel()
        assert scanner.cancelled is True

    @patch('subprocess.Popen')
    def test_cancel_terminates_process(self, mock_popen):
        """CLAM-029: Cancel terminates running process"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        scanner = ClamAVScanner()
        scanner.process = mock_process
        scanner.cancel()

        mock_process.terminate.assert_called_once()

    def test_cancel_no_process(self):
        """CLAM-030: Cancel handles no process gracefully"""
        scanner = ClamAVScanner()
        scanner.cancel()  # Should not raise


class TestClamAVScannerIsScanning:
    """Test is_scanning() method"""

    def test_is_scanning_no_process(self):
        """CLAM-031: is_scanning returns False when no process"""
        scanner = ClamAVScanner()
        assert scanner.is_scanning() is False

    def test_is_scanning_process_running(self):
        """CLAM-032: is_scanning returns True when process running"""
        scanner = ClamAVScanner()
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Still running
        scanner.process = mock_process
        assert scanner.is_scanning() is True

    def test_is_scanning_process_finished(self):
        """CLAM-033: is_scanning returns False when process finished"""
        scanner = ClamAVScanner()
        mock_process = MagicMock()
        mock_process.poll.return_value = 0  # Finished
        scanner.process = mock_process
        assert scanner.is_scanning() is False
