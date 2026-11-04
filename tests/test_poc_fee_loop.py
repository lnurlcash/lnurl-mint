"""Regression tests for the fee/bounds config validation (2026-08-17 review,
F-4 - originally PoC B2).

Pre-fix, config.py put no upper bound on fee_ppm (plain `int = 0`)
and nothing validated the bounds surface at startup: FEE_PPM >=
1_000_000 made _min_sendable_msat's walk non-terminating (fee >= amount at
every step, so the net can never clear min_mint_msat) - a single env var
turned every GET /p and LUD-16 alias into a permanent 100%-CPU hang (proven
live against a uvicorn subprocess during the review: those two endpoints
never answered, everything else did, each hanging sync handler pinning an
anyio threadpool worker forever). Sibling gaps: min_sendable >
max_sendable (every amount rejects), health_check interval 0 (busy-loops
getinfo against the node), negative base_fee.

The fix is startup validation (pydantic Field bounds + a model validator),
so a poisonous config fails AT BOOT with a clear ValidationError instead of
hanging the first request. These tests pin the bounds, plus the defensive
iteration cap in _min_sendable_msat itself (a settings object mutated
after construction, as tests do, bypasses pydantic - the cap turns the
hang into a loud error even then).
"""

import threading

import pytest
from pydantic import ValidationError

from lnurl_mint.config import Settings, settings
from lnurl_mint.router import _min_sendable_msat


def test_fee_ppm_at_or_above_100_percent_rejected_at_startup():
    for ppm in (1_000_000, 1_000_001, 2_000_000):
        with pytest.raises(ValidationError):
            Settings(fee_ppm=ppm)


def test_fee_ppm_above_the_practical_bound_is_also_rejected():
    # even 999_999 ppm is legal-terminating in theory but costs ~10M loop
    # iterations of CPU per lnaddress request - the bound sits at 100_000
    # (10%), keeping the _min_sendable_msat walk under ~100 steps
    with pytest.raises(ValidationError):
        Settings(fee_ppm=100_001)
    assert Settings(fee_ppm=100_000).fee_ppm == 100_000


def test_negative_fee_values_rejected_at_startup():
    with pytest.raises(ValidationError):
        Settings(fee_ppm=-1)
    with pytest.raises(ValidationError):
        Settings(base_fee_msat=-1)


def test_inverted_sendable_bounds_rejected_at_startup():
    # min > max would reject every /p/cb amount as both too low and too
    # high - caught here, not by a wallet's first attempt
    with pytest.raises(ValidationError):
        Settings(min_sendable_msat=2_000_000, max_sendable_msat=1_000_000)
    ok = Settings(min_sendable_msat=1_000_000, max_sendable_msat=1_000_000)
    assert ok.min_sendable_msat == ok.max_sendable_msat


def test_zero_health_check_interval_rejected_at_startup():
    # 0 busy-loops getinfo against the funding source (server.py's monitor
    # sleeps exactly this between probes)
    with pytest.raises(ValidationError):
        Settings(funding_source_health_check_interval_seconds=0)


def test_min_sendable_walk_terminates_under_worst_legal_config(monkeypatch):
    """The most hostile config that still passes validation: ppm at the
    bound (100_000), a large base fee, and a min_mint far above
    min_sendable - the walk climbs far, but must terminate quickly (well
    under the defensive cap)."""
    monkeypatch.setattr(settings, "fee_ppm", 100_000)
    monkeypatch.setattr(settings, "base_fee_msat", 1_000_000)
    monkeypatch.setattr(settings, "min_mint_msat", 1_000_000)
    monkeypatch.setattr(settings, "min_sendable_msat", 10_000)
    value = _min_sendable_msat()
    # net of fee at the result clears min_mint, by construction
    fee = settings.base_fee_msat + (value * settings.fee_ppm) // 1_000_000
    fee = -(-fee // 1000) * 1000
    assert value - fee >= settings.min_mint_msat


def test_iteration_cap_turns_a_pathological_config_into_a_loud_error(monkeypatch):
    """Defense in depth: a settings object mutated after construction
    bypasses pydantic validation (tests do exactly this). If fee settings
    ever again make the walk non-terminating, the cap must convert the
    silent 100%-CPU hang into a raised error - proven here by the walk
    RAISING (quickly) rather than a thread still spinning 2s later."""
    monkeypatch.setattr(settings, "fee_ppm", 1_000_000)  # bypasses validation, as pre-fix configs could
    monkeypatch.setattr(settings, "base_fee_msat", 0)
    monkeypatch.setattr(settings, "min_mint_msat", 10_000)
    monkeypatch.setattr(settings, "min_sendable_msat", 10_000)

    result = {}

    def run():
        try:
            result["value"] = _min_sendable_msat()
        except RuntimeError as exc:
            result["error"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=30.0)
    assert not t.is_alive(), "_min_sendable_msat hung despite the iteration cap"
    assert "error" in result and "did not terminate" in str(result["error"])
