from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any
from uuid import uuid4

import pytest

from pydenticore import IdentityResult, UserLoginInfo, UserManager, IdentityOptions, UpperLookupNormalizer, RoleManager
from pydenticore.interfaces.stores import *
from pydenticore.security.claims import Claim
from pydenticore.types import GUID, UserProtokol, RoleProtokol, TRole, TUser


@dataclass
class MockUser(UserProtokol[str]):
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
class MockRole(RoleProtokol[str]):
    concurrency_stamp: Optional[GUID] = field(default=None)
    id: str = field(default=str(uuid4()))
    name: Optional[str] = field(default='admin')
    normalized_name: Optional[str] = field(default='admin'.upper())


class MockRoleStore(IRoleClaimStore, IRoleStore):
    def create_model_from_dict(self, **kwargs: Any) -> TRole:
        pass

    async def all(self) -> list[TRole]:
        pass

    async def create(self, role: TRole) -> IdentityResult:
        pass

    async def update(self, role: TRole) -> IdentityResult:
        pass

    async def delete(self, role: TRole) -> IdentityResult:
        pass

    async def find_by_id(self, role_id: str) -> Optional[TRole]:
        pass

    async def find_by_name(self, normalized_name: str) -> Optional[TRole]:
        pass

    async def get_role_id(self, role: TRole) -> str:
        pass

    async def get_role_name(self, role: TRole) -> Optional[str]:
        pass

    async def set_role_name(self, role: TRole, role_name: Optional[str]) -> None:
        pass

    async def get_normalized_role_name(self, role: TRole) -> Optional[str]:
        pass

    async def set_normalized_role_name(self, role: TRole, normalized_name: Optional[str]) -> None:
        pass

    async def get_claims(self, role: TRole) -> list[Claim]:
        pass

    async def add_claim(self, role: TRole, claims: Claim) -> None:
        pass

    async def remove_claim(self, role: TRole, claim: Claim) -> None:
        pass


class MockUserStore(
    IUserAuthenticationTokenStore,
    IUserAuthenticatorKeyStore,
    IUserClaimStore,
    IUserEmailStore,
    IUserLockoutStore,
    IUserLoginStore,
    IUserPasswordStore,
    IUserPhoneNumberStore,
    IUserRoleStore,
    IUserSecurityStampStore,
    IUserTwoFactorRecoveryCodeStore,
    IUserTwoFactorStore,
    IProtectedUserStore,
    IUserStore
):
    async def get_token(self, user: TUser, login_provider: str, name: str) -> Optional[str]:
        pass

    async def remove_token(self, user: TUser, login_provider: str, name: str) -> None:
        pass

    async def set_token(self, user: TUser, login_provider: str, name: str, value: Optional[str]) -> None:
        pass

    async def get_authenticator_key(self, user: TUser) -> Optional[str]:
        pass

    async def set_authenticator_key(self, user: TUser, key: str) -> None:
        pass

    async def add_claims(self, user: TUser, *claims: Claim) -> None:
        pass

    async def get_claims(self, user: TUser) -> list[Claim]:
        pass

    async def get_users_for_claim(self, claim: Claim) -> list[TUser]:
        pass

    async def remove_claims(self, user: TUser, *claims: Claim) -> None:
        pass

    async def replace_claim(self, user: TUser, claim: Claim, new_claim: Claim) -> None:
        pass

    async def find_by_email(self, normalized_email: str) -> Optional[TUser]:
        pass

    async def get_email(self, user: TUser) -> Optional[str]:
        pass

    async def set_email(self, user: TUser, email: Optional[str]) -> None:
        pass

    async def get_email_confirmed(self, user: TUser) -> bool:
        pass

    async def get_normalized_email(self, user: TUser) -> Optional[str]:
        pass

    async def set_normalized_email(self, user: TUser, normalized_email: Optional[str]) -> None:
        pass

    async def set_email_confirmed(self, user: TUser, confirmed: bool) -> None:
        pass

    async def get_access_failed_count(self, user: TUser) -> int:
        pass

    async def get_lockout_enabled(self, user: TUser) -> bool:
        pass

    async def get_lockout_end_date(self, user: TUser) -> Optional[datetime]:
        pass

    async def increment_access_failed_count(self, user: TUser) -> int:
        pass

    async def reset_access_failed_count(self, user: TUser) -> None:
        pass

    async def set_lockout_enabled(self, user: TUser, enabled: bool) -> None:
        pass

    async def set_lockout_end_date(self, user: TUser, lockout_end: datetime) -> None:
        pass

    async def add_login(self, user: TUser, login: UserLoginInfo) -> None:
        pass

    async def find_by_login(self, login_provider: str, provider_key: str) -> Optional[TUser]:
        pass

    async def get_logins(self, user: TUser) -> list[UserLoginInfo]:
        pass

    async def remove_login(self, user: TUser, login_provider: str, provider_key: str) -> None:
        pass

    async def get_password_hash(self, user: TUser) -> Optional[str]:
        pass

    async def has_password(self, user: TUser) -> bool:
        pass

    async def set_password_hash(self, user: TUser, password_hash: str | None) -> None:
        pass

    async def get_phone_number(self, user: TUser) -> Optional[str]:
        pass

    async def set_phone_number(self, user: TUser, phone_number: Optional[str]) -> None:
        pass

    async def get_phone_number_confirmed(self, user: TUser) -> bool:
        pass

    async def set_phone_number_confirmed(self, user: TUser, confirmed: bool) -> None:
        pass

    async def add_to_role(self, user: TUser, normalized_role_name: str) -> None:
        pass

    async def get_roles(self, user: TUser) -> list[str]:
        pass

    async def get_users_in_role(self, normalized_role_name: str) -> list[TUser]:
        pass

    async def is_in_role(self, user: TUser, normalized_role_name: str) -> bool:
        pass

    async def remove_from_role(self, user: TUser, normalized_role_name: str) -> None:
        pass

    async def get_security_stamp(self, user: TUser) -> Optional[str]:
        pass

    async def set_security_stamp(self, user: TUser, stamp: str) -> None:
        pass

    async def count_codes(self, user: TUser) -> int:
        pass

    async def redeem_code(self, user: TUser, code: str) -> bool:
        pass

    async def replace_codes(self, user: TUser, *recovery_codes: str) -> None:
        pass

    async def get_two_factor_enabled(self, user: TUser) -> bool:
        pass

    async def set_two_factor_enabled(self, user: TUser, enabled: bool) -> None:
        pass

    def create_model_from_dict(self, **kwargs: Any) -> TUser:
        pass

    async def all(self) -> list[TUser]:
        pass

    async def create(self, user: TUser) -> IdentityResult:
        pass

    async def update(self, user: TUser) -> IdentityResult:
        pass

    async def delete(self, user: TUser) -> IdentityResult:
        pass

    async def find_by_id(self, user_id: str) -> Optional[TUser]:
        pass

    async def find_by_name(self, normalized_username: str) -> Optional[TUser]:
        pass

    async def get_user_id(self, user: TUser) -> str:
        pass

    async def get_username(self, user: TUser) -> Optional[str]:
        pass

    async def set_username(self, user: TUser, username: Optional[str]) -> None:
        pass

    async def get_normalized_username(self, user: TUser) -> Optional[str]:
        pass

    async def set_normalized_username(self, user: TUser, normalized_name: Optional[str]) -> None:
        pass


@pytest.fixture
def user_manager():
    return UserManager(
        MockUserStore(),
        key_normalizer=UpperLookupNormalizer()
    )


@pytest.fixture
def role_manager():
    return RoleManager(
        MockRoleStore(),
        key_normalizer=UpperLookupNormalizer()
    )
