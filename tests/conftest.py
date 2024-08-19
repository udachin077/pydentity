from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import uuid4

import pytest

from pydentity.types import GUID, UserProtokol, RoleProtokol


@dataclass
class User(UserProtokol[str]):
    access_failed_count: int = field(default=0)
    concurrency_stamp: Optional[GUID] = field(default=None)
    email: Optional[str] = field(default='john.doe@example.com')
    email_confirmed: bool = field(default=True)
    id: str = field(default=str(uuid4()))
    lockout_enabled: bool = field(default=True)
    lockout_end: Optional[datetime] = field(default=None)
    normalized_email: Optional[str] = field(default='john.doe@example.com'.upper())
    normalized_username: Optional[str] = field(default='john.doe'.upper())
    password_hash: Optional[str] = field(default=None)
    phone_number: Optional[str] = field(default=None)
    phone_number_confirmed: bool = field(default=False)
    security_stamp: Optional[GUID] = field(default=str(uuid4()))
    two_factor_enabled: bool = field(default=True)
    username: Optional[str] = field(default='john.doe')


@dataclass
class Role(RoleProtokol[str]):
    concurrency_stamp: Optional[GUID] = field(default=None)
    id: str = field(default=str(uuid4()))
    name: Optional[str] = field(default='admin')
    normalized_name: Optional[str] = field(default='admin'.upper())


