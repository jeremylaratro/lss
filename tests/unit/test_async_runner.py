"""
Tests for ids_suite.ui.components.async_runner module
Tests async threading patterns for UI operations

These tests use threading.Event for proper synchronization instead of
time.sleep() to avoid flaky behavior on slow systems.
"""

import pytest
from unittest.mock import MagicMock, patch, call
import threading


class TestAsyncRunnerInit:
    """Test AsyncRunner initialization"""

    def test_init_stores_root(self):
        """AsyncRunner should store the root window"""
        from ids_suite.ui.components.async_runner import AsyncRunner
        mock_root = MagicMock()
        runner = AsyncRunner(mock_root)
        assert runner.root is mock_root

    def test_init_creates_empty_thread_list(self):
        """AsyncRunner should initialize with empty active threads"""
        from ids_suite.ui.components.async_runner import AsyncRunner
        mock_root = MagicMock()
        runner = AsyncRunner(mock_root)
        assert runner._active_threads == []


class TestAsyncRunnerRun:
    """Test AsyncRunner.run() method"""

    @pytest.fixture
    def runner(self):
        """Create AsyncRunner with mock root that executes callbacks synchronously"""
        from ids_suite.ui.components.async_runner import AsyncRunner
        mock_root = MagicMock()
        # Execute after() callbacks immediately for deterministic testing
        mock_root.after = lambda delay, fn: fn()
        return AsyncRunner(mock_root)

    def test_run_returns_thread(self, runner):
        """run() should return a Thread object"""
        completed = threading.Event()
        def work():
            completed.set()
            return "result"

        thread = runner.run(work_fn=work)
        assert isinstance(thread, threading.Thread)
        completed.wait(timeout=2)

    def test_run_executes_work_function(self, runner):
        """
        BUSINESS LOGIC: Work function must execute in background thread.
        This is critical for UI responsiveness - blocking operations
        must not freeze the main thread.
        """
        work_executed = threading.Event()
        execution_thread = []

        def work():
            execution_thread.append(threading.current_thread())
            work_executed.set()
            return "done"

        main_thread = threading.current_thread()
        thread = runner.run(work_fn=work)

        # Wait for work to complete
        assert work_executed.wait(timeout=2), "Work function was not executed"

        # Verify work ran in a different thread (non-blocking)
        assert len(execution_thread) == 1
        assert execution_thread[0] != main_thread, \
            "Work must run in background thread, not main thread"

    def test_run_calls_on_complete_with_result(self, runner):
        """
        BUSINESS LOGIC: on_complete callback receives work result.
        This is how async operations return data to the UI layer.
        """
        result_received = threading.Event()
        results = []

        def work():
            return {"data": "test_value", "count": 42}

        def on_complete(result):
            results.append(result)
            result_received.set()

        thread = runner.run(work_fn=work, on_complete=on_complete)
        assert result_received.wait(timeout=2), "on_complete was not called"

        # Verify the exact result was passed
        assert len(results) == 1
        assert results[0] == {"data": "test_value", "count": 42}

    def test_run_calls_on_error_on_exception(self, runner):
        """
        BUSINESS LOGIC: Exceptions in work function must be caught and
        passed to on_error callback, NOT propagated to crash the thread.
        """
        error_received = threading.Event()
        errors = []

        def work():
            raise ValueError("Database connection failed")

        def on_error(e):
            errors.append(e)
            error_received.set()

        thread = runner.run(work_fn=work, on_error=on_error)
        assert error_received.wait(timeout=2), "on_error was not called"

        # Verify exception details preserved
        assert len(errors) == 1
        assert isinstance(errors[0], ValueError)
        assert "Database connection failed" in str(errors[0])

    def test_run_calls_on_finally_after_success(self, runner):
        """
        BUSINESS LOGIC: on_finally is called after success.
        Used for cleanup like hiding progress indicators.
        """
        finally_called = threading.Event()
        call_order = []

        def work():
            call_order.append('work')
            return "result"

        def on_complete(result):
            call_order.append('complete')

        def on_finally():
            call_order.append('finally')
            finally_called.set()

        thread = runner.run(
            work_fn=work,
            on_complete=on_complete,
            on_finally=on_finally
        )
        assert finally_called.wait(timeout=2), "on_finally was not called"

        # Verify call order: work → complete → finally
        assert call_order == ['work', 'complete', 'finally']

    def test_run_calls_on_finally_after_error(self, runner):
        """
        BUSINESS LOGIC: on_finally MUST be called even when work fails.
        Critical for UI state cleanup (progress bars, disabled buttons).
        """
        finally_called = threading.Event()
        call_order = []

        def work():
            call_order.append('work')
            raise RuntimeError("Operation failed")

        def on_error(e):
            call_order.append('error')

        def on_finally():
            call_order.append('finally')
            finally_called.set()

        thread = runner.run(
            work_fn=work,
            on_error=on_error,
            on_finally=on_finally
        )
        assert finally_called.wait(timeout=2), "on_finally not called after error"

        # Verify finally called even after error
        assert call_order == ['work', 'error', 'finally']

    def test_run_adds_thread_to_active_list(self, runner):
        """
        BUSINESS LOGIC: Active threads must be tracked for:
        1. Preventing duplicate operations
        2. Graceful shutdown
        3. Progress monitoring
        """
        work_started = threading.Event()
        work_continue = threading.Event()

        def work():
            work_started.set()
            work_continue.wait(timeout=5)
            return "done"

        thread = runner.run(work_fn=work)

        # Wait for work to start
        assert work_started.wait(timeout=2)

        # Thread should be in active list while running
        assert thread in runner._active_threads

        # Let it complete
        work_continue.set()
        thread.join(timeout=2)

    def test_run_creates_daemon_thread(self, runner):
        """
        BUSINESS LOGIC: Threads must be daemon threads so they don't
        prevent application exit. Users shouldn't have to wait for
        background operations to finish when closing the app.
        """
        work_started = threading.Event()
        work_continue = threading.Event()

        def work():
            work_started.set()
            work_continue.wait(timeout=5)
            return "done"

        thread = runner.run(work_fn=work)
        work_started.wait(timeout=2)

        assert thread.daemon is True, \
            "Background threads must be daemon to allow clean app exit"

        work_continue.set()

    def test_on_complete_not_called_on_error(self, runner):
        """
        BUSINESS LOGIC: on_complete must NOT be called when work fails.
        Calling both on_complete and on_error would cause confusing behavior.
        """
        completed = threading.Event()
        complete_called = []
        error_called = []

        def work():
            raise ValueError("Failed")

        def on_complete(result):
            complete_called.append(result)

        def on_error(e):
            error_called.append(e)
            completed.set()

        thread = runner.run(
            work_fn=work,
            on_complete=on_complete,
            on_error=on_error
        )
        completed.wait(timeout=2)

        assert len(complete_called) == 0, "on_complete should not be called on error"
        assert len(error_called) == 1

    def test_none_result_passed_to_on_complete(self, runner):
        """
        BUSINESS LOGIC: None is a valid return value from work.
        Must distinguish between "returned None" and "didn't complete".
        """
        completed = threading.Event()
        results = []

        def work():
            return None  # Explicit None return

        def on_complete(result):
            results.append(('received', result))
            completed.set()

        thread = runner.run(work_fn=work, on_complete=on_complete)
        completed.wait(timeout=2)

        # None should be passed to on_complete
        assert results == [('received', None)]


class TestAsyncRunnerRunWithProgress:
    """Test AsyncRunner.run_with_progress() method"""

    @pytest.fixture
    def runner(self):
        """Create AsyncRunner with mock root"""
        from ids_suite.ui.components.async_runner import AsyncRunner
        mock_root = MagicMock()
        mock_root.after = lambda delay, fn: fn()
        return AsyncRunner(mock_root)

    def test_run_with_progress_calls_progress_start(self, runner):
        """
        BUSINESS LOGIC: Progress indicator must show BEFORE work starts.
        User needs visual feedback that operation is in progress.
        """
        completed = threading.Event()
        call_sequence = []

        def progress_start(msg):
            call_sequence.append(('start', msg))

        def progress_stop():
            call_sequence.append(('stop',))
            completed.set()

        def work():
            call_sequence.append(('work',))
            return "result"

        thread = runner.run_with_progress(
            work_fn=work,
            progress_start=progress_start,
            progress_stop=progress_stop,
            progress_message="Loading data..."
        )
        completed.wait(timeout=2)

        # Progress start should be called first with correct message
        assert call_sequence[0] == ('start', "Loading data...")
        assert 'work' in [c[0] if isinstance(c, tuple) and len(c) > 0 else c for c in call_sequence]

    def test_run_with_progress_calls_progress_stop_on_complete(self, runner):
        """
        BUSINESS LOGIC: Progress indicator MUST be hidden after completion.
        Leaving it visible would confuse users about operation state.
        """
        completed = threading.Event()
        stop_called = []

        def progress_start(msg):
            pass

        def progress_stop():
            stop_called.append(True)
            completed.set()

        thread = runner.run_with_progress(
            work_fn=lambda: "result",
            progress_start=progress_start,
            progress_stop=progress_stop
        )
        completed.wait(timeout=2)

        assert stop_called == [True]

    def test_run_with_progress_calls_progress_stop_on_error(self, runner):
        """
        BUSINESS LOGIC: Progress indicator MUST be hidden even on error.
        This is critical - a stuck progress bar is a bad UX.
        """
        completed = threading.Event()
        stop_called = []

        def progress_start(msg):
            pass

        def progress_stop():
            stop_called.append(True)
            completed.set()

        def work():
            raise RuntimeError("API request failed")

        thread = runner.run_with_progress(
            work_fn=work,
            on_error=lambda e: None,
            progress_start=progress_start,
            progress_stop=progress_stop
        )
        completed.wait(timeout=2)

        assert stop_called == [True], \
            "Progress must be hidden even when operation fails"

    def test_run_with_progress_passes_on_complete(self, runner):
        """Progress mode should still call on_complete with result"""
        completed = threading.Event()
        results = []

        def on_complete(result):
            results.append(result)
            completed.set()

        thread = runner.run_with_progress(
            work_fn=lambda: {"status": "success"},
            on_complete=on_complete
        )
        completed.wait(timeout=2)

        assert results == [{"status": "success"}]


class TestAsyncRunnerRunSequence:
    """Test AsyncRunner.run_sequence() method"""

    @pytest.fixture
    def runner(self):
        """Create AsyncRunner with mock root"""
        from ids_suite.ui.components.async_runner import AsyncRunner
        mock_root = MagicMock()
        mock_root.after = lambda delay, fn: fn()
        return AsyncRunner(mock_root)

    def test_run_sequence_executes_all_tasks_in_order(self, runner):
        """
        BUSINESS LOGIC: Tasks must execute sequentially in order.
        Used for dependent operations like: fetch config → apply config → restart
        """
        completed = threading.Event()
        execution_order = []

        tasks = [
            (lambda: execution_order.append(1) or "result1", None),
            (lambda: execution_order.append(2) or "result2", None),
            (lambda: execution_order.append(3) or "result3", None),
        ]

        thread = runner.run_sequence(
            tasks,
            on_all_complete=completed.set
        )
        completed.wait(timeout=2)

        assert execution_order == [1, 2, 3], \
            "Tasks must execute in exact order provided"

    def test_run_sequence_calls_task_completion_handlers(self, runner):
        """
        BUSINESS LOGIC: Each task can have its own completion handler.
        Allows UI updates between sequential operations.
        """
        completed = threading.Event()
        task_results = []

        def task1_complete(r):
            task_results.append(('task1', r))

        def task2_complete(r):
            task_results.append(('task2', r))

        tasks = [
            (lambda: "config_loaded", task1_complete),
            (lambda: "rules_applied", task2_complete),
        ]

        thread = runner.run_sequence(
            tasks,
            on_all_complete=completed.set
        )
        completed.wait(timeout=2)

        assert ('task1', 'config_loaded') in task_results
        assert ('task2', 'rules_applied') in task_results

    def test_run_sequence_calls_on_all_complete(self, runner):
        """on_all_complete should be called after all tasks finish"""
        all_complete = threading.Event()

        tasks = [
            (lambda: "result1", None),
            (lambda: "result2", None),
        ]

        thread = runner.run_sequence(
            tasks,
            on_all_complete=all_complete.set
        )

        assert all_complete.wait(timeout=2), \
            "on_all_complete must be called when all tasks finish"

    def test_run_sequence_stops_on_error(self, runner):
        """
        BUSINESS LOGIC: If any task fails, remaining tasks must NOT execute.
        Critical for dependent operations - don't apply config if fetch failed.
        """
        completed = threading.Event()
        executed = []
        errors = []

        def task1():
            executed.append(1)
            return "ok"

        def task2():
            executed.append(2)
            raise ValueError("Config validation failed")

        def task3():
            executed.append(3)
            return "should not reach"

        tasks = [
            (task1, None),
            (task2, None),
            (task3, None),
        ]

        def on_error(e):
            errors.append(e)
            completed.set()

        thread = runner.run_sequence(tasks, on_error=on_error)
        completed.wait(timeout=2)

        # Task 3 should NOT execute after task 2 fails
        assert executed == [1, 2], \
            "Sequence must stop at first failure"
        assert len(errors) == 1
        assert "Config validation failed" in str(errors[0])

    def test_run_sequence_on_all_complete_not_called_on_error(self, runner):
        """
        BUSINESS LOGIC: on_all_complete must NOT be called if any task fails.
        Prevents false success indication.
        """
        error_event = threading.Event()
        all_complete_called = []

        def failing_task():
            raise RuntimeError("Failed")

        tasks = [
            (failing_task, None),
        ]

        thread = runner.run_sequence(
            tasks,
            on_all_complete=lambda: all_complete_called.append(True),
            on_error=lambda e: error_event.set()
        )
        error_event.wait(timeout=2)

        # Give a moment for any incorrect calls
        thread.join(timeout=1)

        assert all_complete_called == [], \
            "on_all_complete must not be called when sequence fails"


class TestAsyncRunnerThreadManagement:
    """Test AsyncRunner thread management methods"""

    @pytest.fixture
    def runner(self):
        """Create AsyncRunner with mock root"""
        from ids_suite.ui.components.async_runner import AsyncRunner
        mock_root = MagicMock()
        mock_root.after = lambda delay, fn: fn()
        return AsyncRunner(mock_root)

    def test_get_active_count_returns_zero_initially(self, runner):
        """get_active_count() should return 0 for new runner"""
        assert runner.get_active_count() == 0

    def test_get_active_count_tracks_running_threads(self, runner):
        """
        BUSINESS LOGIC: Active thread count used to:
        1. Show "X operations in progress" to user
        2. Prevent duplicate concurrent operations
        3. Warn before closing app with pending operations
        """
        work_started = threading.Event()
        work_continue = threading.Event()

        def work():
            work_started.set()
            work_continue.wait(timeout=5)
            return "done"

        # Start two background operations
        runner.run(work_fn=work)
        runner.run(work_fn=work)

        # Wait for both to start
        work_started.wait(timeout=2)

        # Should report 2 active threads
        assert runner.get_active_count() == 2

        # Release threads
        work_continue.set()

    def test_get_active_count_cleans_finished_threads(self, runner):
        """Finished threads should be removed from active count"""
        completed = threading.Event()

        def quick_work():
            return "done"

        thread = runner.run(
            work_fn=quick_work,
            on_complete=lambda r: completed.set()
        )
        completed.wait(timeout=2)
        thread.join(timeout=1)

        # After completion, count should be 0
        count = runner.get_active_count()
        assert count == 0

    def test_wait_all_waits_for_completion(self, runner):
        """
        BUSINESS LOGIC: wait_all() used for graceful shutdown.
        Application should wait for all operations to complete before exiting.
        """
        completed_count = []
        work_started = threading.Event()

        def work():
            work_started.set()
            return "done"

        def on_complete(r):
            completed_count.append(1)

        runner.run(work_fn=work, on_complete=on_complete)
        runner.run(work_fn=work, on_complete=on_complete)

        work_started.wait(timeout=2)
        result = runner.wait_all(timeout=2)

        assert result is True
        assert len(completed_count) == 2

    def test_wait_all_returns_false_on_timeout(self, runner):
        """
        BUSINESS LOGIC: wait_all() must not hang forever.
        Returns False if operations don't complete in time.
        """
        work_started = threading.Event()
        work_continue = threading.Event()

        def slow_work():
            work_started.set()
            work_continue.wait(timeout=10)  # Will timeout
            return "done"

        runner.run(work_fn=slow_work)
        work_started.wait(timeout=2)

        # Short timeout should return False
        result = runner.wait_all(timeout=0.1)
        assert result is False

        # Cleanup
        work_continue.set()


class TestAsyncMethodDecorator:
    """Test @async_method decorator"""

    def test_decorator_requires_runner_attribute(self):
        """
        BUSINESS LOGIC: Decorated class MUST have runner attribute.
        This enforces the pattern that all async operations go through
        the centralized AsyncRunner for consistent behavior.
        """
        from ids_suite.ui.components.async_runner import async_method

        class NoRunner:
            @async_method()
            def do_work(self):
                return "result"

        obj = NoRunner()
        with pytest.raises(AttributeError) as exc_info:
            obj.do_work()
        assert "must have 'runner' attribute" in str(exc_info.value)

    def test_decorator_calls_completion_handler(self):
        """
        BUSINESS LOGIC: Decorator automatically calls {method}_complete.
        Convention-based callback discovery reduces boilerplate.
        """
        from ids_suite.ui.components.async_runner import AsyncRunner, async_method

        mock_root = MagicMock()
        mock_root.after = lambda delay, fn: fn()

        completed = threading.Event()
        results = []

        class DataFetcher:
            def __init__(self):
                self.runner = AsyncRunner(mock_root)

            @async_method()
            def fetch_data(self):
                return {"users": ["alice", "bob"]}

            def fetch_data_complete(self, data):
                results.append(data)
                completed.set()

        fetcher = DataFetcher()
        thread = fetcher.fetch_data()
        completed.wait(timeout=2)

        assert results == [{"users": ["alice", "bob"]}]

    def test_decorator_calls_error_handler(self):
        """
        BUSINESS LOGIC: Decorator calls {method}_error on exception.
        Centralizes error handling for async operations.
        """
        from ids_suite.ui.components.async_runner import AsyncRunner, async_method

        mock_root = MagicMock()
        mock_root.after = lambda delay, fn: fn()

        completed = threading.Event()
        errors = []

        class DataFetcher:
            def __init__(self):
                self.runner = AsyncRunner(mock_root)

            @async_method()
            def fetch_data(self):
                raise ConnectionError("Network unreachable")

            def fetch_data_error(self, e):
                errors.append(e)
                completed.set()

        fetcher = DataFetcher()
        thread = fetcher.fetch_data()
        completed.wait(timeout=2)

        assert len(errors) == 1
        assert isinstance(errors[0], ConnectionError)

    def test_decorator_uses_custom_error_handler(self):
        """Custom error_handler parameter overrides convention"""
        from ids_suite.ui.components.async_runner import AsyncRunner, async_method

        mock_root = MagicMock()
        mock_root.after = lambda delay, fn: fn()

        completed = threading.Event()
        errors = []

        class DataFetcher:
            def __init__(self):
                self.runner = AsyncRunner(mock_root)

            @async_method(error_handler='handle_any_error')
            def fetch_data(self):
                raise ValueError("Bad input")

            def handle_any_error(self, e):
                errors.append(f"handled: {e}")
                completed.set()

        fetcher = DataFetcher()
        thread = fetcher.fetch_data()
        completed.wait(timeout=2)

        assert "handled: Bad input" in errors[0]

    def test_decorator_with_progress_message(self):
        """
        BUSINESS LOGIC: progress_message triggers show/hide progress.
        Integrates with app's progress indicator system.
        """
        from ids_suite.ui.components.async_runner import AsyncRunner, async_method

        mock_root = MagicMock()
        mock_root.after = lambda delay, fn: fn()

        completed = threading.Event()
        progress_calls = []

        class MockApp:
            def show_progress(self, msg):
                progress_calls.append(('show', msg))

            def hide_progress(self):
                progress_calls.append(('hide',))

        class DataLoader:
            def __init__(self):
                self.runner = AsyncRunner(mock_root)
                self.app = MockApp()

            @async_method(progress_message="Fetching records...")
            def load_records(self):
                return ["record1", "record2"]

            def load_records_complete(self, data):
                completed.set()

        loader = DataLoader()
        thread = loader.load_records()
        completed.wait(timeout=2)

        assert ('show', "Fetching records...") in progress_calls
        assert ('hide',) in progress_calls
