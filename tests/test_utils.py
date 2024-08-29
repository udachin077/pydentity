from datetime import timedelta, UTC

import pytest

from pydentity.utils import datetime, is_none_or_empty


def test_datetime_utcnow():
    assert (datetime.now(UTC) <= datetime.utcnow()) is True


@pytest.mark.parametrize("now, _timedelta, result", {
    (datetime.now(UTC), timedelta(minutes=2), True),
    (datetime.now(UTC), timedelta(minutes=-2), False)
})
def test_datetime_add(now, _timedelta, result):
    assert (now < (now.add(_timedelta))) is result


@pytest.mark.parametrize("now, days, result", {
    (datetime.now(UTC), 2, True),
    (datetime.now(UTC), -2, False)
})
def test_datetime_add_days(now: datetime, days, result):
    assert (now < (now.add_days(days))) is result


@pytest.mark.parametrize("now, seconds, result", {
    (datetime.now(UTC), 2, True),
    (datetime.now(UTC), -2, False)
})
def test_datetime_add_seconds(now: datetime, seconds, result):
    assert (now < (now.add_seconds(seconds))) is result


@pytest.mark.parametrize("now, microseconds, result", {
    (datetime.now(UTC), 2, True),
    (datetime.now(UTC), -2, False)
})
def test_datetime_add_microseconds(now: datetime, microseconds, result):
    assert (now < (now.add_microseconds(microseconds))) is result


@pytest.mark.parametrize("now, milliseconds, result", {
    (datetime.now(UTC), 2, True),
    (datetime.now(UTC), -2, False)
})
def test_datetime_add_milliseconds(now: datetime, milliseconds, result):
    assert (now < (now.add_milliseconds(milliseconds))) is result


@pytest.mark.parametrize("now, minutes, result", {
    (datetime.now(UTC), 2, True),
    (datetime.now(UTC), -2, False)
})
def test_datetime_add_minutes(now: datetime, minutes, result):
    assert (now < (now.add_minutes(minutes))) is result


@pytest.mark.parametrize("now, hours, result", {
    (datetime.now(UTC), 2, True),
    (datetime.now(UTC), -2, False)
})
def test_datetime_add_hours(now: datetime, hours, result):
    assert (now < (now.add_hours(hours))) is result


@pytest.mark.parametrize("now, weeks, result", {
    (datetime.now(UTC), 2, True),
    (datetime.now(UTC), -2, False)
})
def test_datetime_add_weeks(now: datetime, weeks, result):
    assert (now < (now.add_weeks(weeks))) is result


def test_is_none_or_empty():
    assert is_none_or_empty(None) is True
    assert is_none_or_empty("") is True
    assert is_none_or_empty(" ") is True
    assert is_none_or_empty("None") is False
