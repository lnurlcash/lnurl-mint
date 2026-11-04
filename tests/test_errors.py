import logging

import pytest

import lnurl_mint.errors as errors_module


def test_log_internal_error_does_not_crash_when_error_log_is_unwritable(monkeypatch, tmp_path):
    # regression: an unwritable data directory (see errors.py's delay=True)
    # must not crash a request that hits log_internal_error - error.log is
    # a diagnostic side channel, not something a caller's own request
    # should ever fail over
    unwritable_dir = tmp_path / "unwritable"
    unwritable_dir.mkdir(mode=0o500)
    broken_logger = logging.getLogger("lnurl_mint.errors.test_unwritable")
    broken_logger.setLevel(logging.ERROR)
    broken_logger.propagate = False
    broken_logger.addHandler(errors_module._ErrorFileHandler(str(unwritable_dir / "error.log"), delay=True))
    monkeypatch.setattr(errors_module, "_logger", broken_logger)

    reference = errors_module.log_internal_error("boom", ValueError("something broke"))

    assert "reference:" in reference


@pytest.mark.parametrize("raise_exceptions", [True, False])
def test_log_internal_error_falls_back_to_stdout_when_error_log_is_unwritable(
    monkeypatch, tmp_path, caplog, raise_exceptions
):
    # regression: _logger has propagate=False specifically so a successful
    # error.log write never *also* shows up in stdout/docker logs - but
    # that meant a failed write vanished with no trace anywhere, not even a
    # hint that error.log itself needed attention. It must fall back to the
    # root logger (docker logs) instead of disappearing silently.
    unwritable_dir = tmp_path / "unwritable"
    unwritable_dir.mkdir(mode=0o500)
    broken_logger = logging.getLogger("lnurl_mint.errors.test_fallback")
    broken_logger.setLevel(logging.ERROR)
    broken_logger.propagate = False
    broken_logger.addHandler(errors_module._ErrorFileHandler(str(unwritable_dir / "error.log"), delay=True))
    monkeypatch.setattr(errors_module, "_logger", broken_logger)
    monkeypatch.setattr(logging, "raiseExceptions", raise_exceptions)

    with caplog.at_level(logging.ERROR):
        reference = errors_module.log_internal_error("boom", ValueError("something broke"))

    ref_id = reference.split("reference: ")[1].rstrip(").")
    assert any(ref_id in r.message and "error.log unwritable" in r.message for r in caplog.records)


def test_log_internal_error_still_logs_normally_when_writable(tmp_path, monkeypatch):
    logger = logging.getLogger("lnurl_mint.errors.test_writable")
    logger.setLevel(logging.ERROR)
    logger.propagate = False
    log_path = tmp_path / "error.log"
    logger.addHandler(errors_module._ErrorFileHandler(str(log_path), delay=True))
    monkeypatch.setattr(errors_module, "_logger", logger)

    reference = errors_module.log_internal_error("boom", ValueError("something broke"))

    logged = log_path.read_text()
    assert logged.count("boom") == 1
    assert reference.split("reference: ")[1].rstrip(").") in logged
