import dataclasses
from datetime import datetime as _datetime, timedelta, UTC
from typing import Any
from uuid import NAMESPACE_DNS, UUID, uuid5, getnode

import pyotp

from pydentity.exc import ArgumentNoneException

__all__ = (
    'asdict',
    'datetime',
    'generate_uri',
    'get_device_uuid',
    'is_none_or_empty',
)


class datetime(_datetime):
    @classmethod
    def utcnow(cls) -> 'datetime':
        return datetime.now(UTC)

    def add(self, _timedelta: timedelta, /) -> 'datetime':
        return self.__add__(_timedelta)

    def add_days(self, days: float, /) -> 'datetime':
        return self.add(timedelta(days=days))

    def add_seconds(self, seconds: float, /) -> 'datetime':
        return self.add(timedelta(seconds=seconds))

    def add_microseconds(self, microseconds: float, /) -> 'datetime':
        return self.add(timedelta(microseconds=microseconds))

    def add_milliseconds(self, milliseconds: float, /) -> 'datetime':
        return self.add(timedelta(milliseconds=milliseconds))

    def add_minutes(self, minutes: float, /) -> 'datetime':
        return self.add(timedelta(minutes=minutes))

    def add_hours(self, hours: float, /) -> 'datetime':
        return self.add(timedelta(hours=hours))

    def add_weeks(self, weeks: float, /) -> 'datetime':
        return self.add(timedelta(weeks=weeks))


def is_none_or_empty(_string: str | None, /) -> bool:
    return _string is None or not _string or _string.isspace()


def get_device_uuid() -> str:
    return str(uuid5(NAMESPACE_DNS, str(UUID(int=getnode()))))


def asdict(obj: Any, exclude_none: bool = True) -> dict[str, Any]:
    if exclude_none:
        return dataclasses.asdict(obj, dict_factory=lambda x: {k: v for (k, v) in x if v is not None})
    return dataclasses.asdict(obj)


def generate_uri(secret: str, name: str, app_name: str) -> str:
    if not secret:
        raise ArgumentNoneException('secret')
    if not name:
        raise ArgumentNoneException('name')
    if not app_name:
        raise ArgumentNoneException('app_name')

    return pyotp.TOTP(secret).provisioning_uri(name=name, issuer_name=app_name)
