import datetime
import uuid
from typing import TypeVar, Protocol, Optional, Callable

_T = TypeVar('_T')

Predicate = Callable[[_T], bool]
Action = Callable[[_T], None]

GUID = uuid.UUID

TKey = TypeVar('TKey')


class UserProtokol(Protocol[TKey]):
    access_failed_count: int
    concurrency_stamp: Optional[GUID]
    email: Optional[str]
    email_confirmed: bool
    id: TKey
    lockout_enabled: bool
    lockout_end: Optional[datetime.datetime]
    normalized_email: Optional[str]
    normalized_username: Optional[str]
    password_hash: Optional[str]
    phone_number: Optional[str]
    phone_number_confirmed: bool
    security_stamp: Optional[GUID]
    two_factor_enabled: bool
    username: Optional[str]


class RoleProtokol(Protocol[TKey]):
    concurrency_stamp: Optional[GUID]
    id: TKey
    name: Optional[str]
    normalized_name: Optional[str]


class UserRoleProtokol(Protocol[TKey]):
    user_id: TKey
    role_id: TKey


class UserClaimProtokol(Protocol[TKey]):
    claim_type: Optional[str]
    claim_value: Optional[str]
    user_id: TKey


class UserLoginProtokol(Protocol[TKey]):
    login_provider: str
    provider_key: str
    provider_display_name: Optional[str]
    user_id: TKey


class UserTokenProtokol(Protocol[TKey]):
    login_provider: str
    name: str
    value: Optional[str]
    user_id: TKey


TUser = TypeVar('TUser', bound=UserProtokol)
TRole = TypeVar('TRole', bound=RoleProtokol)
TUserRole = TypeVar('TUserRole', bound=UserRoleProtokol)
TUserClaim = TypeVar('TUserClaim', bound=UserClaimProtokol)
TUserLogin = TypeVar('TUserLogin', bound=UserLoginProtokol)
TUserToken = TypeVar('TUserToken', bound=UserTokenProtokol)
