"""A timer's calendar read into operations. Software, holds no rule of its own.

    read_timer(args, schema) -> {(operation, container, part), ...}
    elapses(expression, start, end) -> sorted list of the times the expression fires in (start, end]

`args` is `{"on_calendar": [expressions], "unit": "<unit it starts>"}`, as a tool that installs a timer takes it. Each
expression is read as systemd reads `OnCalendar=` (systemd.time(7), "Calendar Events"), in UTC:
`[weekdays] [date] [time]`, with the shorthands `minutely hourly daily weekly monthly yearly annually quarterly
semiannually`. Weekdays are names or three-letter abbreviations, any case, in lists (`,`) and ranges (`..`). A date is
`Y-M-D` or `M-D`; a time is `H:M` or `H:M:S`; each part is `*`, a number, a list, a range `a..b` or a repetition
`a/b` (`a..b/c`), never from `*`. Weekday ranges are written `..` or `-`. A two-digit year is 2000 to 2069 (00 to 69)
or 1970 to 1999 (70 to 99). Seconds may have a fraction. A day written `M~D` counts from the end of the month (no
repetition, no day 0). A repetition `a/b` with no end whose second value would pass the part's maximum (`30/30` in
minutes) is refused, as systemd refuses it. A time zone by name reads the times as its local times: a local time the
clock skips never fires, one it repeats fires once, at the first. A missing date is every day; a missing time is
midnight. An expression the reader does not read raises `ValueError` and does not pass.

The reader computes every time the expressions fire, merged, from `schema["from"]` for `schema["years"]` years, and
reads:
- `("limit", "runs_in_15_minutes", n)`: the most runs in any 15 minutes (a run at the same second counted once);
- `("run_at", "hours", "HH")` for each hour of the day some run falls in;
- `("start", "units", <unit>)`.
"""
import calendar
import re
from datetime import datetime, timedelta, timezone

_DAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6, "monday": 0, "tuesday": 1, "wednesday": 2,
         "thursday": 3, "friday": 4, "saturday": 5, "sunday": 6}
_SHORT = {"minutely": "*-*-* *:*:00", "hourly": "*-*-* *:00:00", "daily": "*-*-* 00:00:00", "monthly": "*-*-01 00:00:00",
          "weekly": "Mon *-*-* 00:00:00", "yearly": "*-01-01 00:00:00", "annually": "*-01-01 00:00:00",
          "quarterly": "*-01,04,07,10-01 00:00:00", "semiannually": "*-01,07-01 00:00:00"}


def _component(text, lo, hi, scale=1):
    """`*`, a number, a list, a range, a repetition: the set of values in [lo, hi]. `*` takes no repetition (`*/15`
    is refused, as systemd refuses it). With `scale` (seconds), a value may have a fraction and is kept in millionths."""
    num = r"\d+(?:\.\d+)?" if scale > 1 else r"\d+"
    out = set()
    for item in text.split(","):
        m = re.fullmatch(rf"(\*|{num})(?:\.\.({num}))?(?:/({num}))?", item)
        if not m:
            raise ValueError(f"a part that is not read: {item!r}")
        a, b, step = m.groups()
        val = (lambda x: round(float(x) * scale)) if scale > 1 else int
        if a == "*":
            if b is not None or step is not None:
                raise ValueError("a range or a repetition from *")
            start, end = lo * scale, hi * scale
        else:
            start = val(a)
            end = val(b) if b is not None else ((hi + 1) * scale - 1 if step else start)
        if step is not None and b is None and val(a) + val(step) > hi * scale:   # systemd: a repetition that never
            raise ValueError(f"a repetition that never repeats: {item!r}")       # repeats (`30/30`) is refused
        step = val(step) if step else scale
        if step == 0 or start < lo * scale or start > hi * scale or end >= (hi + 1) * scale or end < start:
            raise ValueError(f"a value out of range: {item!r}")
        out |= set(range(start, end + 1, step))
    return out


def _weekdays(text):
    out = set()
    for item in text.split(","):
        a, sep, b = item.partition("..")
        if not sep and "-" in item:                  # `Mon-Fri` is a range too
            a, sep, b = item.partition("-")
        if a.lower() not in _DAYS or (sep and b.lower() not in _DAYS):
            raise ValueError(f"a weekday that is not read: {item!r}")
        x, y = _DAYS[a.lower()], _DAYS[b.lower()] if sep else _DAYS[a.lower()]
        if y < x:
            raise ValueError(f"a weekday range backwards: {item!r}")
        out |= set(range(x, y + 1))
    return out


def parse(expr):
    """The expression as sets: weekdays, years, months, days (or days from the end), hours, minutes, seconds."""
    if not isinstance(expr, str) or not expr.strip():
        raise ValueError("an empty expression")
    words = expr.split()
    if len(words) == 1 and re.fullmatch(r"@\d+", words[0]):     # an instant in seconds since 1970
        return {"at": datetime.fromtimestamp(int(words[0][1:]), tz=timezone.utc)}
    zone = None
    if len(words) > 1 and "/" in words[-1] and ":" not in words[-1]:   # a time zone by name: the times are its local times
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        try:
            zone = ZoneInfo(words.pop())
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("a time zone that is not known") from None
    if len(words) == 1 and words[0].lower() in _SHORT:
        words = _SHORT[words[0].lower()].split()
    spec = {"weekdays": set(range(7)), "zone": zone}
    if words and re.match(r"[A-Za-z]", words[0]):
        spec["weekdays"] = _weekdays(words.pop(0))
    if words and words[-1].upper() == "UTC":
        words.pop()
    date = time = None
    for w in words:
        if ":" in w and time is None:
            time = w
        elif ("-" in w or "~" in w) and date is None and time is None:
            date = w
        else:
            raise ValueError(f"a word that is not read: {w!r}")
    y, m, d, from_end = "*", "*", "*", False
    if date is not None:
        if "~" in date:
            head, d = date.rsplit("~", 1)
            from_end = True
            parts = head.split("-")
        else:
            parts = date.split("-")
            d = parts.pop()
        if len(parts) == 2:
            y, m = parts
        elif len(parts) == 1:
            m = parts[0]
        else:
            raise ValueError(f"a date that is not read: {date!r}")
    if y != "*" and re.fullmatch(r"\d{2}", y.split("..")[0].split("/")[0].split(",")[0]):
        if not re.fullmatch(r"\d{2}", y):
            raise ValueError("a two-digit year with a list, a range or a repetition")
        y = str(int(y) + (2000 if int(y) < 70 else 1900))   # 00 to 69 are 2000 to 2069, 70 to 99 are 1970 to 1999
    elif y != "*" and re.search(r"(?<!\d)\d{1,3}(?!\d)", y):
        raise ValueError(f"a year that is not four digits: {y!r}")
    years = _component(y, 1970, 2199) if y != "*" else None
    if from_end and ("/" in d or d in ("0", "00")):
        raise ValueError("a day from the end with a repetition, or day 0 from the end")
    spec.update(years=years, months=_component(m, 1, 12), days=_component(d, 1, 31), from_end=from_end)
    h, mi, s = "0", "0", "0"
    if time is not None:
        t = time.split(":")
        if len(t) == 2:
            h, mi = t
        elif len(t) == 3:
            h, mi, s = t
        else:
            raise ValueError(f"a time that is not read: {time!r}")
    spec.update(hours=_component(h, 0, 23), minutes=_component(mi, 0, 59), seconds=_component(s, 0, 59, scale=1000000))
    return spec


def elapses(spec, start, end, stop_at=None):
    """Every time the spec fires in (start, end], in order; stops early past `stop_at` runs."""
    if "at" in spec:
        return [spec["at"]] if start < spec["at"] <= end else []
    zone = spec.get("zone") or timezone.utc
    out, day = [], (start - timedelta(days=1)).date()
    in_day = sorted((h * 3600 + m * 60) * 1000000 + s for h in spec["hours"] for m in spec["minutes"] for s in spec["seconds"])
    while day <= (end + timedelta(days=1)).date():
        last = calendar.monthrange(day.year, day.month)[1]
        dom = (last - day.day + 1) if spec["from_end"] else day.day
        if (day.weekday() in spec["weekdays"] and (spec["years"] is None or day.year in spec["years"])
                and day.month in spec["months"] and dom in spec["days"]):
            for sec in in_day:
                local = datetime(day.year, day.month, day.day) + timedelta(microseconds=sec)
                t = local.replace(tzinfo=zone).astimezone(timezone.utc)
                if zone is not timezone.utc and t.astimezone(zone).replace(tzinfo=None) != local:
                    continue                                 # a local time the clock skips (spring forward) never fires
                if start < t <= end:
                    out.append(t)
                    if stop_at and len(out) >= stop_at:
                        return out
        day += timedelta(days=1)
    return out


def most_in_window(times, minutes=15):
    best, j = 0, 0
    for i, t in enumerate(times):
        while times[j] <= t - timedelta(minutes=minutes):
            j += 1
        best = max(best, i - j + 1)
    return best


def read_timer(args, schema):
    if not isinstance(args, dict):
        raise ValueError("a timer is an object")
    exprs = args.get("on_calendar")
    if isinstance(exprs, str):
        exprs = [exprs]
    if not exprs or not all(isinstance(e, str) for e in exprs):
        raise ValueError("a timer with no calendar")
    start = datetime.fromisoformat(schema["from"]).replace(tzinfo=timezone.utc)
    end = start.replace(year=start.year + schema["years"])
    times = set()
    for e in exprs:
        times |= set(elapses(parse(e), start, end, stop_at=100000))
    times = sorted(times)   # a run every few seconds: the first 100,000 tell
    ops = {("limit", "runs_in_15_minutes", most_in_window(times)), ("start", "units", str(args.get("unit", "")))}
    ops |= {("run_at", "hours", f"{t.hour:02d}") for t in times}
    return ops
