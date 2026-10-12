from collections import deque, Counter
import threading
from typing import Any, Tuple, Optional


class SlidingWindow:
    """Sliding time-window event tracker.
    
    Maintains a FIFO queue of (timestamp, value) pairs and a synchronized frequency Counter.
    Time complexity for add() is O(1) amortized: expired elements are popped from the left
    and the Counter decremented.
    """

    def __init__(self, window_seconds: float):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = float(window_seconds)
        self.events = deque()  # stores (timestamp: float, value: Any)
        self.values = Counter()
        self._lock = threading.Lock()

    def add(self, ts: float, value: Any) -> None:
        """Add an event at timestamp ts and expire old events outside the window."""
        with self._lock:
            self.events.append((ts, value))
            self.values[value] += 1
            self._expire_before(ts - self.window_seconds)

    def expire_to(self, now: float) -> None:
        """Explicitly purge events older than (now - window_seconds)."""
        with self._lock:
            self._expire_before(now - self.window_seconds)

    def _expire_before(self, cutoff_ts: float) -> None:
        while self.events and self.events[0][0] < cutoff_ts:
            _, old_val = self.events.popleft()
            self.values[old_val] -= 1
            if self.values[old_val] <= 0:
                del self.values[old_val]

    @property
    def count(self) -> int:
        """Total number of events in the active window."""
        with self._lock:
            return len(self.events)

    @property
    def distinct(self) -> int:
        """Total number of distinct values in the active window."""
        with self._lock:
            return len(self.values)

    @property
    def span(self) -> float:
        """Elapsed time between the earliest and latest event in the window."""
        with self._lock:
            if not self.events:
                return 0.0
            return self.events[-1][0] - self.events[0][0]

    def is_idle(self, now: float) -> bool:
        """Check if no events have been received in the last window_seconds."""
        with self._lock:
            if not self.events:
                return True
            return (now - self.events[-1][0]) > self.window_seconds

    def get_values(self) -> Counter:
        with self._lock:
            return self.values.copy()

    def clear(self) -> None:
        with self._lock:
            self.events.clear()
            self.values.clear()
