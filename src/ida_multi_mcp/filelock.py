"""Cross-platform file locking for ida-multi-mcp.

Uses fcntl.flock on Unix and msvcrt.locking on Windows.
"""

import os
import sys
import time


class FileLockTimeout(Exception):
    """Raised when file lock acquisition times out."""
    pass


class FileLock:
    """Cross-platform file lock using context manager.

    Usage:
        with FileLock("path/to/file.lock"):
            # exclusive access to the resource
    """

    def __init__(self, lock_path: str, timeout: float = 5.0):
        """
        Args:
            lock_path: Path to the lock file
            timeout: Maximum seconds to wait for lock (default 5.0)
        """
        self.lock_path = lock_path
        self.timeout = timeout
        self._fd: int | None = None

    def acquire(self) -> None:
        """Acquire the file lock."""
        os.makedirs(os.path.dirname(self.lock_path) or ".", exist_ok=True)
        self._fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR)

        if sys.platform == "win32":
            self._acquire_windows()
        else:
            self._acquire_unix()

    def release(self) -> None:
        """Release the file lock."""
        if self._fd is None:
            return

        if sys.platform == "win32":
            self._release_windows()
        else:
            self._release_unix()

        os.close(self._fd)
        self._fd = None

    def _acquire_unix(self) -> None:
        import fcntl
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    os.close(self._fd)
                    self._fd = None
                    raise FileLockTimeout(
                        f"Could not acquire lock on {self.lock_path} "
                        f"within {self.timeout}s"
                    )
                time.sleep(0.05)

    def _release_unix(self) -> None:
        import fcntl
        fcntl.flock(self._fd, fcntl.LOCK_UN)

    def _acquire_windows(self) -> None:
        import msvcrt
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                return
            except (OSError, IOError):
                if time.monotonic() >= deadline:
                    os.close(self._fd)
                    self._fd = None
                    raise FileLockTimeout(
                        f"Could not acquire lock on {self.lock_path} "
                        f"within {self.timeout}s"
                    )
                time.sleep(0.05)

    def _release_windows(self) -> None:
        import msvcrt
        try:
            msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        except (OSError, IOError):
            pass  # Already unlocked

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()
