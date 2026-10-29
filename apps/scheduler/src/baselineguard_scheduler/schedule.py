from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class InvalidCron(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CronField:
    values: frozenset[int]
    wildcard: bool


@dataclass(frozen=True, slots=True)
class CronSchedule:
    minute: CronField
    hour: CronField
    day_of_month: CronField
    month: CronField
    day_of_week: CronField

    @classmethod
    def parse(cls, expression: str) -> CronSchedule:
        fields = expression.split()
        if len(fields) != 5:
            raise InvalidCron("cron expression must contain exactly five fields")
        return cls(
            _parse_field(fields[0], 0, 59),
            _parse_field(fields[1], 0, 23),
            _parse_field(fields[2], 1, 31),
            _parse_field(fields[3], 1, 12),
            _parse_field(fields[4], 0, 7, sunday_alias=True),
        )

    def matches(self, local: datetime) -> bool:
        weekday = (local.weekday() + 1) % 7
        minute_hour_month = (
            local.minute in self.minute.values
            and local.hour in self.hour.values
            and local.month in self.month.values
        )
        if not minute_hour_month:
            return False
        dom_matches = local.day in self.day_of_month.values
        dow_matches = weekday in self.day_of_week.values
        if self.day_of_month.wildcard:
            return dow_matches
        if self.day_of_week.wildcard:
            return dom_matches
        return dom_matches or dow_matches

    def matches_day(self, local_date: date) -> bool:
        weekday = (local_date.weekday() + 1) % 7
        if local_date.month not in self.month.values:
            return False
        dom_matches = local_date.day in self.day_of_month.values
        dow_matches = weekday in self.day_of_week.values
        if self.day_of_month.wildcard:
            return dow_matches
        if self.day_of_week.wildcard:
            return dom_matches
        return dom_matches or dow_matches


def _parse_field(
    source: str, minimum: int, maximum: int, *, sunday_alias: bool = False
) -> CronField:
    wildcard = source == "*"
    values: set[int] = set()
    if not source:
        raise InvalidCron("cron fields cannot be empty")
    for part in source.split(","):
        if not part:
            raise InvalidCron("cron lists cannot contain empty items")
        base, slash, step_text = part.partition("/")
        if slash:
            if not step_text.isascii() or not step_text.isdigit() or int(step_text) < 1:
                raise InvalidCron("cron step must be a positive integer")
            step = int(step_text)
        else:
            step = 1
        if base == "*":
            start, end = minimum, maximum
        elif "-" in base:
            start_text, separator, end_text = base.partition("-")
            if (
                not separator
                or not start_text.isascii()
                or not start_text.isdigit()
                or not end_text.isascii()
                or not end_text.isdigit()
            ):
                raise InvalidCron("cron range is invalid")
            start, end = int(start_text), int(end_text)
            if start > end:
                raise InvalidCron("cron ranges cannot wrap")
        else:
            if slash or not base.isascii() or not base.isdigit():
                raise InvalidCron("cron field value is invalid")
            start = end = int(base)
        if start < minimum or end > maximum:
            raise InvalidCron("cron value is outside the field's supported range")
        selected = range(start, end + 1, step)
        values.update(0 if sunday_alias and value == 7 else value for value in selected)
    return CronField(frozenset(values), wildcard)


def next_occurrence(
    schedule: CronSchedule | str,
    *,
    after: datetime,
    timezone: str,
    max_days: int = 3660,
) -> datetime:
    """Return the next UTC occurrence, skipping nonexistent local minutes.

    Ambiguous fall-back minutes run once at fold=0 (the earlier UTC instant), as
    required by the schedule contract. The after time is exclusive. Search is bounded
    so malformed or unreachable expressions cannot loop indefinitely.
    """
    parsed = CronSchedule.parse(schedule) if isinstance(schedule, str) else schedule
    if after.tzinfo is None or after.utcoffset() is None:
        raise ValueError("after must be timezone-aware")
    if not 1 <= max_days <= 3660:
        raise ValueError("max_days must be between 1 and 3660")
    try:
        zone = ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError("timezone must be a valid IANA timezone") from None
    current = after.astimezone(zone).replace(tzinfo=None, second=0, microsecond=0)
    current += timedelta(minutes=1)
    for day_offset in range(max_days + 1):
        candidate_date = current.date() + timedelta(days=day_offset)
        if not parsed.matches_day(candidate_date):
            continue
        for hour in sorted(parsed.hour.values):
            for minute in sorted(parsed.minute.values):
                wall_time = datetime.combine(candidate_date, time(hour, minute))
                if wall_time < current:
                    continue
                first_fold = wall_time.replace(tzinfo=zone, fold=0)
                utc_candidate = first_fold.astimezone(UTC)
                # Round-trip validation excludes spring-forward wall times that never exist.
                if (
                    utc_candidate.astimezone(zone).replace(tzinfo=None) == wall_time
                    and utc_candidate > after
                ):
                    return utc_candidate
    raise ValueError("no matching cron occurrence found within the configured search horizon")
