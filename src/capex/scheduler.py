from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class ScheduledAttack:
    offset_seconds: float
    attack_index: int
    repeat_index: int


def build_schedule(
    *,
    attack_count: int,
    repeats_per_attack: int,
    allowed_duration_seconds: int,
) -> list[ScheduledAttack]:
    total = attack_count * repeats_per_attack
    if total <= 0:
        return []

    interval = allowed_duration_seconds / total
    schedule: list[ScheduledAttack] = []

    counter = 0
    for attack_index in range(attack_count):
        for repeat_index in range(repeats_per_attack):
            schedule.append(
                ScheduledAttack(
                    offset_seconds=counter * interval,
                    attack_index=attack_index,
                    repeat_index=repeat_index,
                )
            )
            counter += 1

    return schedule
