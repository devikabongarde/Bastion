from datetime import UTC, datetime

import pytest

from baselineguard_scheduler.schedule import CronSchedule, InvalidCron, next_occurrence


@pytest.mark.parametrize(
    "expression",
    ["", "* * * *", "60 * * * *", "1-9-2 * * * *", "*/0 * * * *", "5/2 * * * *", "1,,2 * * * *"],
)
def test_cron_rejects_invalid_or_unbounded_fields(expression: str):
    with pytest.raises(InvalidCron):
        CronSchedule.parse(expression)


def test_cron_supports_lists_ranges_steps_and_sunday_alias():
    schedule = CronSchedule.parse("*/15 8-10 1,15 * 0,7")
    assert schedule.matches(datetime(2026, 11, 1, 8, 30))  # Sunday, day 1
    assert not schedule.matches(datetime(2026, 11, 2, 8, 30))


def test_next_occurrence_is_exclusive_and_returns_utc():
    result = next_occurrence(
        "0 * * * *",
        after=datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
        timezone="UTC",
    )
    assert result == datetime(2026, 1, 1, 11, 0, tzinfo=UTC)


def test_spring_forward_nonexistent_local_time_is_skipped():
    result = next_occurrence(
        "15 2 * * *",
        after=datetime(2026, 3, 8, 6, 59, tzinfo=UTC),
        timezone="America/New_York",
    )
    assert result == datetime(2026, 3, 9, 6, 15, tzinfo=UTC)


def test_fall_back_ambiguous_time_runs_once_at_earlier_fold():
    first = next_occurrence(
        "30 1 * * *",
        after=datetime(2026, 11, 1, 3, 59, tzinfo=UTC),
        timezone="America/New_York",
    )
    after_first = next_occurrence(
        "30 1 * * *",
        after=datetime(2026, 11, 1, 5, 45, tzinfo=UTC),
        timezone="America/New_York",
    )
    assert first == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)
    assert after_first == datetime(2026, 11, 2, 6, 30, tzinfo=UTC)


def test_schedule_rejects_naive_time_unknown_zone_and_unbounded_horizon():
    with pytest.raises(ValueError, match="timezone-aware"):
        next_occurrence("0 0 * * *", after=datetime(2026, 1, 1), timezone="UTC")
    with pytest.raises(ValueError, match="IANA"):
        next_occurrence(
            "0 0 * * *",
            after=datetime(2026, 1, 1, tzinfo=UTC),
            timezone="Invalid/Zone",
        )
    with pytest.raises(ValueError, match="max_days"):
        next_occurrence(
            "0 0 * * *",
            after=datetime(2026, 1, 1, tzinfo=UTC),
            timezone="UTC",
            max_days=3661,
        )
