from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(slots=True, frozen=True)
class ScheduledAttack:
    offset_seconds: float
    attack_index: int
    repeat_index: int


def build_schedule(
    *,
    repeats_per_attack: Sequence[int],
    allowed_duration_seconds: int,
) -> list[ScheduledAttack]:
    """Build a schedule spreading each attack's repeats evenly across the full duration.

    Each attack's repeats are spaced independently over the whole
    ``allowed_duration_seconds`` window, so attacks with fewer repeats than
    others are not clustered into the earliest part of the run.
    """
    schedule: list[ScheduledAttack] = []

    for attack_index, repeats in enumerate(repeats_per_attack):
        if repeats <= 0:
            continue

        interval = allowed_duration_seconds / repeats
        for repeat_index in range(repeats):
            schedule.append(
                ScheduledAttack(
                    offset_seconds=repeat_index * interval,
                    attack_index=attack_index,
                    repeat_index=repeat_index,
                )
            )

    schedule.sort(key=lambda item: item.offset_seconds)
    return schedule
