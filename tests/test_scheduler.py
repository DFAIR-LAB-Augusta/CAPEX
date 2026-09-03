from __future__ import annotations

from capex.scheduler import build_schedule


def test_build_schedule_count() -> None:
    schedule = build_schedule(
        repeats_per_attack=[3, 3, 3, 3],
        allowed_duration_seconds=120,
    )
    assert len(schedule) == 12


def test_build_schedule_spreads_uneven_repeats_across_full_duration() -> None:
    # Attack 0 has far fewer repeats than attack 1. Previously, attack 0's
    # runs would all cluster in the first repeat-index rounds instead of
    # being spread across the whole window.
    schedule = build_schedule(
        repeats_per_attack=[2, 10],
        allowed_duration_seconds=100,
    )

    attack_0_offsets = [item.offset_seconds for item in schedule if item.attack_index == 0]
    assert attack_0_offsets == [0.0, 50.0]

    # The schedule as a whole must be sorted by offset regardless of which
    # attack contributed each entry.
    offsets = [item.offset_seconds for item in schedule]
    assert offsets == sorted(offsets)


def test_build_schedule_skips_attacks_with_zero_repeats() -> None:
    schedule = build_schedule(
        repeats_per_attack=[0, 2],
        allowed_duration_seconds=100,
    )

    assert all(item.attack_index == 1 for item in schedule)
    assert len(schedule) == 2


def test_build_schedule_empty_when_no_attacks() -> None:
    assert build_schedule(repeats_per_attack=[], allowed_duration_seconds=100) == []
