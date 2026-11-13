import multiprocessing
import pytest

from run_detector import single_instance_lock


def _try_lock(path, queue):
    try:
        with single_instance_lock(path):
            queue.put("acquired")
    except RuntimeError:
        queue.put("refused")


def test_duplicate_detector_lock(tmp_path):
    path = tmp_path / "detector.sqlite3.lock"
    ctx = multiprocessing.get_context("spawn")
    with single_instance_lock(path):
        queue = ctx.Queue()
        child = ctx.Process(target=_try_lock, args=(path, queue))
        child.start()
        assert queue.get(timeout=10) == "refused"
        child.join(timeout=10)
        assert child.exitcode == 0
    with single_instance_lock(path):
        pass
