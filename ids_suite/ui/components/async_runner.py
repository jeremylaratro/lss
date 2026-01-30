"""
Async Runner Component
Encapsulates the threading pattern used throughout main_window.py
"""

import threading
from typing import Callable, Optional, Any
import tkinter as tk


class AsyncRunner:
    """
    Utility for running operations asynchronously in background threads.

    Extracts the common pattern from main_window.py:
    1. Define a work function
    2. Define a completion handler
    3. Start a daemon thread
    4. Use root.after(0, ...) to update UI from main thread

    This class provides a cleaner, more testable interface for this pattern.
    """

    def __init__(self, root: tk.Tk):
        """
        Initialize AsyncRunner.

        Args:
            root: Tkinter root window for scheduling UI updates
        """
        self.root = root
        self._active_threads = []
        self._threads_lock = threading.Lock()  # Thread safety for _active_threads

    def run(
        self,
        work_fn: Callable[[], Any],
        on_complete: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        on_finally: Optional[Callable[[], None]] = None
    ) -> threading.Thread:
        """
        Run work in background thread and handle result on main thread.

        Args:
            work_fn: Function to execute in background (returns result)
            on_complete: Called on main thread with result if work succeeds
            on_error: Called on main thread with exception if work fails
            on_finally: Called on main thread after completion or error

        Returns:
            The created thread (already started)

        Example:
            def fetch_data():
                # Long running operation
                return requests.get('http://api.example.com/data').json()

            def update_ui(data):
                # Update UI with fetched data
                self.listbox.insert(tk.END, data['items'])

            def handle_error(error):
                messagebox.showerror("Error", str(error))

            runner.run(
                work_fn=fetch_data,
                on_complete=update_ui,
                on_error=handle_error
            )
        """
        def thread_worker():
            result = None
            error = None

            # Execute work in background thread
            try:
                result = work_fn()
            except Exception as e:
                error = e

            # Schedule UI updates on main thread
            def update_ui():
                try:
                    if error:
                        if on_error:
                            on_error(error)
                    else:
                        if on_complete:
                            on_complete(result)
                finally:
                    if on_finally:
                        on_finally()

                    # Clean up thread reference (thread-safe)
                    with self._threads_lock:
                        if thread in self._active_threads:
                            self._active_threads.remove(thread)

            self.root.after(0, update_ui)

        # Create and start daemon thread
        thread = threading.Thread(target=thread_worker, daemon=True)
        with self._threads_lock:
            self._active_threads.append(thread)
        thread.start()

        return thread

    def run_with_progress(
        self,
        work_fn: Callable[[], Any],
        on_complete: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        progress_start: Optional[Callable[[str], None]] = None,
        progress_stop: Optional[Callable[[], None]] = None,
        progress_message: str = "Working..."
    ) -> threading.Thread:
        """
        Run work with automatic progress indicator management.

        This is the pattern used throughout main_window.py with
        show_progress() and hide_progress().

        Args:
            work_fn: Function to execute in background
            on_complete: Called with result on success
            on_error: Called with exception on failure
            progress_start: Function to show progress (receives message)
            progress_stop: Function to hide progress
            progress_message: Message to show during work

        Returns:
            The created thread

        Example:
            runner.run_with_progress(
                work_fn=lambda: scan_directory('/home'),
                on_complete=lambda results: self.display_results(results),
                progress_start=self.app.show_progress,
                progress_stop=self.app.hide_progress,
                progress_message="Scanning directory..."
            )
        """
        # Show progress
        if progress_start:
            progress_start(progress_message)

        def on_finally():
            # Hide progress
            if progress_stop:
                progress_stop()

        return self.run(
            work_fn=work_fn,
            on_complete=on_complete,
            on_error=on_error,
            on_finally=on_finally
        )

    def run_sequence(
        self,
        tasks: list[tuple[Callable[[], Any], Optional[Callable[[Any], None]]]],
        on_all_complete: Optional[Callable[[], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None
    ) -> threading.Thread:
        """
        Run multiple tasks sequentially in background.

        Args:
            tasks: List of (work_fn, on_complete) tuples
            on_all_complete: Called after all tasks complete
            on_error: Called if any task fails (stops sequence)

        Returns:
            The created thread

        Example:
            runner.run_sequence([
                (lambda: fetch_config(), lambda cfg: self.apply_config(cfg)),
                (lambda: fetch_rules(), lambda rules: self.load_rules(rules)),
                (lambda: fetch_stats(), lambda stats: self.update_stats(stats)),
            ], on_all_complete=lambda: print("All done!"))
        """
        def sequential_worker():
            results = []

            for work_fn, task_complete in tasks:
                try:
                    result = work_fn()
                    results.append(result)

                    # Call task completion on main thread
                    if task_complete:
                        def update(r=result, tc=task_complete):
                            tc(r)
                        self.root.after(0, update)

                except Exception as e:
                    # Error stops sequence
                    if on_error:
                        self.root.after(0, lambda: on_error(e))
                    return

            # All tasks completed
            if on_all_complete:
                self.root.after(0, on_all_complete)

        thread = threading.Thread(target=sequential_worker, daemon=True)
        with self._threads_lock:
            self._active_threads.append(thread)
        thread.start()

        return thread

    def get_active_count(self) -> int:
        """Get number of active background threads."""
        # Clean up finished threads (thread-safe)
        with self._threads_lock:
            self._active_threads = [t for t in self._active_threads if t.is_alive()]
            return len(self._active_threads)

    def wait_all(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for all active threads to complete.

        Args:
            timeout: Maximum time to wait in seconds (None = wait forever)

        Returns:
            True if all threads finished, False if timeout occurred
        """
        with self._threads_lock:
            threads_copy = self._active_threads[:]
        for thread in threads_copy:
            thread.join(timeout)
            if thread.is_alive():
                return False
        return True


# Convenience decorator for async methods
def async_method(
    progress_message: Optional[str] = None,
    error_handler: Optional[str] = None
):
    """
    Decorator to make a method run asynchronously.

    The decorated method should accept 'self' and return a value.
    Results will be passed to the method name with '_complete' suffix.

    Args:
        progress_message: Optional progress message to show
        error_handler: Optional name of error handler method

    Example:
        class MyTab(BaseTab):
            def __init__(self, parent, app):
                super().__init__(parent, app)
                self.runner = AsyncRunner(app.root)

            @async_method(progress_message="Loading data...")
            def load_data(self):
                # This runs in background thread
                return fetch_data_from_api()

            def load_data_complete(self, data):
                # This runs on main thread
                self.display_data(data)

            def load_data_error(self, error):
                messagebox.showerror("Error", str(error))
    """
    def decorator(method):
        def wrapper(self, *args, **kwargs):
            # Get the runner instance
            if not hasattr(self, 'runner'):
                raise AttributeError(
                    f"{self.__class__.__name__} must have 'runner' attribute "
                    "(AsyncRunner instance)"
                )

            runner: AsyncRunner = self.runner

            # Define work function
            def work():
                return method(self, *args, **kwargs)

            # Find completion handler
            complete_method_name = f"{method.__name__}_complete"
            on_complete = getattr(self, complete_method_name, None)

            # Find error handler
            if error_handler:
                on_error = getattr(self, error_handler, None)
            else:
                error_method_name = f"{method.__name__}_error"
                on_error = getattr(self, error_method_name, None)

            # Get progress handlers
            progress_start = getattr(self.app, 'show_progress', None) if hasattr(self, 'app') else None
            progress_stop = getattr(self.app, 'hide_progress', None) if hasattr(self, 'app') else None

            # Run async
            if progress_message and progress_start and progress_stop:
                return runner.run_with_progress(
                    work_fn=work,
                    on_complete=on_complete,
                    on_error=on_error,
                    progress_start=progress_start,
                    progress_stop=progress_stop,
                    progress_message=progress_message
                )
            else:
                return runner.run(
                    work_fn=work,
                    on_complete=on_complete,
                    on_error=on_error
                )

        return wrapper
    return decorator
