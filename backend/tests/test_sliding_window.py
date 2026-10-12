import pytest
from app.detection.sliding_window import SlidingWindow


def test_sliding_window_add_and_count():
    window = SlidingWindow(window_seconds=10.0)
    window.add(100.0, "A")
    window.add(102.0, "B")
    window.add(104.0, "A")

    assert window.count == 3
    assert window.distinct == 2
    assert window.span == 4.0


def test_sliding_window_expiration():
    window = SlidingWindow(window_seconds=5.0)
    window.add(100.0, "val1")
    window.add(102.0, "val2")
    # Event at 106.0 -> 100.0 is older than (106 - 5 = 101), so val1 expires
    window.add(106.0, "val3")

    assert window.count == 2
    assert "val1" not in window.get_values()
    assert window.distinct == 2


def test_sliding_window_idle_detection():
    window = SlidingWindow(window_seconds=10.0)
    assert window.is_idle(100.0) is True

    window.add(100.0, "val")
    assert window.is_idle(105.0) is False
    assert window.is_idle(111.0) is True


def test_sliding_window_clear():
    window = SlidingWindow(window_seconds=10.0)
    window.add(100.0, "val1")
    window.add(101.0, "val2")
    window.clear()

    assert window.count == 0
    assert window.distinct == 0
