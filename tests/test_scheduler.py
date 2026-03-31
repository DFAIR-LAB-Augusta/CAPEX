from __future__ import annotations

from capex.scheduler import build_schedule


def test_build_schedule_count() -> None:
    schedule = build_schedule(
        attack_count=4,
        repeats_per_attack=3,
        allowed_duration_seconds=120,
    )
    assert len(schedule) == 12
