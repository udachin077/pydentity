from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import uuid4

import pytest

from pydentity.abc.stores import (
    IUserStore,
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
    IRoleStore
)
from pydentity.identity_result import IdentityResult
from pydentity.lookup_normalizer import UpperLookupNormalizer
from pydentity.role_manager import RoleManager
from pydentity.security.claims import Claim
from pydentity.types import (
    UserProtokol,
    RoleProtokol,
    UserRoleProtokol,
    UserClaimProtokol,
    UserLoginProtokol,
    UserTokenProtokol,
    TUser,
    TRole
)
from pydentity.user_login_info import UserLoginInfo
from pydentity.user_manager import UserManager


# password_hash = '$2b$12$rOfUzvH4UOP/ZTXTvkFYbOA6RpkNlqF8L5hN9.ZGx9IFYutBDHQDe'  # P@ssw0rd
@dataclass
class User(UserProtokol[str]):
    id: str = str(uuid4())
    access_failed_count: int = 0
    concurrency_stamp: Optional[str] = None
    email: Optional[str] = None
    email_confirmed: bool = False
    lockout_enabled: bool = False
    lockout_end: Optional[datetime] = None
    normalized_email: Optional[str] = None
    normalized_username: Optional[str] = None
    password_hash: Optional[str] = None
    phone_number: Optional[str] = None
    phone_number_confirmed: bool = False
    security_stamp: Optional[str] = None
    two_factor_enabled: bool = False
    username: Optional[str] = None


@dataclass
class Role(RoleProtokol[str]):
    id: str = str(uuid4())
    concurrency_stamp: Optional[str] = None
    name: Optional[str] = None
    normalized_name: Optional[str] = None


@dataclass
class UserRole(UserRoleProtokol[str]):
    user_id: str = str(uuid4())
    role_id: str = str(uuid4())


@dataclass
class UserClaim(UserClaimProtokol[str]):
    claim_type: Optional[str] = None
    claim_value: Optional[str] = None
    user_id: str = str(uuid4())


@dataclass
class UserLogin(UserLoginProtokol[str]):
    login_provider: str = str(uuid4())
    provider_key: str = str(uuid4())
    provider_display_name: Optional[str] = None
    user_id: str = str(uuid4())


@dataclass
class UserToken(UserTokenProtokol[str]):
    login_provider: str = str(uuid4())
    name: str = str(uuid4())
    value: Optional[str] = None
    user_id: str = str(uuid4())


class DB:
    def __init__(self):
        self.ROLE_ADMIN = str(uuid4())
        self.ROLE_MANAGER = str(uuid4())
        self.ROLE_USER = str(uuid4())

        self.Roles: list[Role] = [
            Role(id=str(uuid4()), name="sysadmin", normalized_name="SYSADMIN"),
            Role(id=self.ROLE_ADMIN, name="admin", normalized_name="ADMIN"),
            Role(id=self.ROLE_MANAGER, name="manager", normalized_name="MANAGER"),
            Role(id=self.ROLE_USER, name="user", normalized_name="USER"),
            Role(id=str(uuid4()), name="guest", normalized_name="GUEST"),
        ]

        self.USER_ALEX = str(uuid4())
        self.USER_MAX = str(uuid4())
        self.USER_ALEXANDRA = str(uuid4())

        self.Users: dict[str, User] = {
            self.USER_ALEX: User(
                id=self.USER_ALEX,
                email="alex@email.com",
                normalized_email="alex@email.com".upper(),
                username="alex@email.com",
                normalized_username="alex@email.com".upper(),
                phone_number="+777777777",
                phone_number_confirmed=True,
                email_confirmed=True,
                two_factor_enabled=True,
            ),
            self.USER_MAX: User(
                id=self.USER_MAX,
                email="max@email.com",
                normalized_email="max@email.com".upper(),
                username="max@email.com",
                normalized_username="max@email.com".upper(),
            ),
            self.USER_ALEXANDRA: User(
                id=self.USER_ALEXANDRA,
                email="alexandra@email.com",
                normalized_email="alexandra@email.com".upper(),
                username="alexandra@email.com",
                normalized_username="alexandra@email.com".upper(),
            ),
        }
        self.UserRoles: list[UserRole] = [
            UserRole(user_id=self.USER_ALEX, role_id=self.ROLE_ADMIN),
            UserRole(user_id=self.USER_MAX, role_id=self.ROLE_MANAGER),
            UserRole(user_id=self.USER_ALEXANDRA, role_id=self.ROLE_USER)
        ]
        self.UserTokens: list[UserToken] = []
        self.UserLogins: list[UserLogin] = []
        self.UserClaims: list[UserClaim] = []


class RoleStore(IRoleStore[Role]):
    def __init__(self, db):
        self.db = db

    def create_model_from_dict(self, **kwargs):
        return Role(**kwargs)

    async def all(self) -> list[TRole]:
        return self.db.Roles

    async def create(self, role: TRole) -> IdentityResult:
        return IdentityResult.success()

    async def update(self, role: TRole) -> IdentityResult:
        return IdentityResult.success()

    async def delete(self, role: TRole) -> IdentityResult:
        return IdentityResult.success()

    async def find_by_id(self, role_id: str) -> Optional[TRole]:
        for _role in self.db.Roles:
            if _role.id == role_id:
                return _role
        return None

    async def find_by_name(self, normalized_name: str) -> Optional[TRole]:
        for _role in self.db.Roles:
            if _role.normalized_name == normalized_name:
                return _role
        return None

    async def get_role_id(self, role: TRole) -> str:
        return role.id

    async def get_role_name(self, role: TRole) -> Optional[str]:
        return role.name

    async def set_role_name(self, role: TRole, role_name: Optional[str]) -> None:
        role.name = role_name

    async def get_normalized_role_name(self, role: TRole) -> Optional[str]:
        return role.normalized_name

    async def set_normalized_role_name(self, role: TRole, normalized_name: Optional[str]) -> None:
        role.normalized_name = normalized_name


class UserStore(
    IUserAuthenticationTokenStore[User],
    IUserAuthenticatorKeyStore[User],
    IUserClaimStore[User],
    IUserEmailStore[User],
    IUserLockoutStore[User],
    IUserLoginStore[User],
    IUserPasswordStore[User],
    IUserPhoneNumberStore[User],
    IUserRoleStore[User],
    IUserSecurityStampStore[User],
    IUserTwoFactorRecoveryCodeStore[User],
    IUserTwoFactorStore[User],
    IUserStore[User]
):
    def __init__(self, db):
        self.db = db

    async def get_token(self, user: TUser, login_provider: str, name: str) -> Optional[str]:
        for ut in self.db.UserTokens:
            if (
                    ut.user_id == user.id and
                    ut.login_provider == login_provider and
                    ut.name == name
            ):
                return ut.value
        return None

    async def remove_token(self, user: TUser, login_provider: str, name: str) -> None:
        index = None
        for i, ut in enumerate(self.db.UserTokens):
            if (
                    ut.user_id == user.id and
                    ut.login_provider == login_provider and
                    ut.name == name
            ):
                index = i
                break

        if index is not None:
            self.db.UserTokens.pop(index)

    async def set_token(self, user: TUser, login_provider: str, name: str, value: Optional[str]) -> None:
        self.db.UserTokens.append(UserToken(user_id=user.id, login_provider=login_provider, name=name, value=value))

    async def get_authenticator_key(self, user: TUser) -> Optional[str]:
        return await self.get_token(user, "TestLoginProvider", "TestAuthenticator")

    async def set_authenticator_key(self, user: TUser, key: str) -> None:
        await self.set_token(user, "TestLoginProvider", "TestAuthenticator", key)

    async def add_claims(self, user: TUser, *claims: Claim) -> None:
        pass

    async def get_claims(self, user: TUser) -> list[Claim]:
        return [Claim(c.claim_type, c.claim_value) for c in self.db.UserClaims if c.user_id == user.id]

    async def get_users_for_claim(self, claim: Claim) -> list[TUser]:
        users = []
        for c in self.db.UserClaims:
            if c.claim_type == claim.type and c.claim_value == claim.value:
                users.append(self.db.Users[c.user_id])
        return users

    async def remove_claims(self, user: TUser, *claims: Claim) -> None:
        remove_claims = []
        for claim in claims:
            for c in self.db.UserClaims:
                if c.claim_type == claim.type and c.claim_value == claim.value and c.user_id == user.id:
                    remove_claims.append(c)

        for rc in remove_claims:
            self.db.UserClaims.remove(rc)

    async def replace_claim(self, user: TUser, claim: Claim, new_claim: Claim) -> None:
        for c in self.db.UserClaims:
            if c.claim_type == claim.type and c.claim_value == claim.value and c.user_id == user.id:
                c.claim_type = new_claim.type
                c.claim_value = new_claim.value
                break

    async def find_by_email(self, normalized_email: str) -> Optional[TUser]:
        for u in self.db.Users.values():
            if u.normalized_email == normalized_email:
                return u
        return None

    async def get_email(self, user: TUser) -> Optional[str]:
        return user.email

    async def set_email(self, user: TUser, email: Optional[str]) -> None:
        user.email = email

    async def get_email_confirmed(self, user: TUser) -> bool:
        return user.email and user.email_confirmed

    async def get_normalized_email(self, user: TUser) -> Optional[str]:
        return user.normalized_email

    async def set_normalized_email(self, user: TUser, normalized_email: Optional[str]) -> None:
        user.normalized_email = normalized_email

    async def set_email_confirmed(self, user: TUser, confirmed: bool) -> None:
        user.email_confirmed = confirmed

    async def get_access_failed_count(self, user: TUser) -> int:
        return user.access_failed_count

    async def get_lockout_enabled(self, user: TUser) -> bool:
        return user.lockout_enabled

    async def get_lockout_end_date(self, user: TUser) -> Optional[datetime]:
        return user.lockout_end

    async def increment_access_failed_count(self, user: TUser) -> int:
        return user.access_failed_count + 1

    async def reset_access_failed_count(self, user: TUser) -> None:
        user.access_failed_count = 0

    async def set_lockout_enabled(self, user: TUser, enabled: bool) -> None:
        user.lockout_enabled = True

    async def set_lockout_end_date(self, user: TUser, lockout_end: datetime) -> None:
        user.lockout_end = lockout_end

    async def add_login(self, user: TUser, login: UserLoginInfo) -> None:
        self.db.UserLogins.append(
            UserLogin(
                login_provider=login.login_provider,
                provider_key=login.provider_key,
                provider_display_name=login.display_name,
                user_id=user.id)
        )

    async def find_by_login(self, login_provider: str, provider_key: str) -> Optional[TUser]:
        for lp in self.db.UserLogins:
            if lp.login_provider == login_provider and lp.provider_key == provider_key:
                return self.db.Users[lp.user_id]
        return None

    async def get_logins(self, user: TUser) -> list[UserLoginInfo]:
        user_infos = []
        for lp in self.db.UserLogins:
            if lp.user_id == user.id:
                user_infos.append(UserLoginInfo(
                    login_provider=lp.login_provider,
                    provider_key=lp.provider_key,
                    display_name=lp.provider_display_name
                ))
        return user_infos

    async def remove_login(self, user: TUser, login_provider: str, provider_key: str) -> None:
        index = None
        for i, lp in enumerate(self.db.UserLogins):
            if lp.user_id == user.id and lp.login_provider == login_provider and lp.provider_key == provider_key:
                index = i
                break

        if index is not None:
            self.db.UserLogins.pop(index)

    async def get_password_hash(self, user: TUser) -> Optional[str]:
        return user.password_hash

    async def has_password(self, user: TUser) -> bool:
        return bool(user.password_hash)

    async def set_password_hash(self, user: TUser, password_hash: str) -> None:
        user.password_hash = password_hash

    async def get_phone_number(self, user: TUser) -> Optional[str]:
        return user.phone_number

    async def set_phone_number(self, user: TUser, phone_number: Optional[str]) -> None:
        user.phone_number = phone_number

    async def get_phone_number_confirmed(self, user: TUser) -> bool:
        return user.phone_number and user.phone_number_confirmed

    async def set_phone_number_confirmed(self, user: TUser, confirmed: bool) -> None:
        user.phone_number_confirmed = confirmed

    async def add_to_role(self, user: TUser, normalized_role_name: str) -> None:
        for role in self.db.Roles:
            if role.normalized_name == normalized_role_name:
                self.db.UserRoles.append(UserRole(user_id=user.id, role_id=role.id))

    async def get_roles(self, user: TUser) -> list[str]:
        role_names = []
        for ur in self.db.UserRoles:
            if ur.user_id == user.id:
                for r in self.db.Roles:
                    if ur.role_id == r.id:
                        role_names.append(r.name)
        return role_names

    async def get_users_in_role(self, normalized_role_name: str) -> list[TUser]:
        users = []
        role = await self.find_by_name(normalized_role_name)
        for ur in self.db.UserRoles:
            if ur.role_id == role.id:
                users.append(self.db.Users[ur.user_id])
        return users

    async def is_in_role(self, user: TUser, normalized_role_name: str) -> bool:
        role = await self.find_by_name(normalized_role_name)
        for ur in self.db.UserRoles:
            if ur.role_id == role.id and ur.user_id == user.id:
                return True
        return False

    async def remove_from_role(self, user: TUser, normalized_role_name: str) -> None:
        role = await self.find_by_name(normalized_role_name)
        index = None
        for i, ur in enumerate(self.db.UserRoles):
            if ur.role_id == role.id and ur.user_id == user.id:
                index = i
                break

        if index is not None:
            self.db.UserRoles.pop(index)

    async def get_security_stamp(self, user: TUser) -> Optional[str]:
        return user.security_stamp

    async def set_security_stamp(self, user: TUser, stamp: str) -> None:
        user.security_stamp = stamp

    async def count_codes(self, user: TUser) -> int:
        merged_codes = (await self.get_token(user, "PydentityRecoveryCodes", "RecoveryCodes")) or ""

        if merged_codes:
            return merged_codes.count(';') + 1

        return 0

    async def redeem_code(self, user: TUser, code: str) -> bool:
        merged_codes = (await self.get_token(user, "PydentityRecoveryCodes", "RecoveryCodes")) or ""
        split_codes = merged_codes.split(';')

        if code in split_codes:
            split_codes.remove(code)
            await self.replace_codes(user, *split_codes)
            return True

        return False

    async def replace_codes(self, user: TUser, *recovery_codes: str) -> None:
        merged_codes = ';'.join(recovery_codes)
        return await self.set_token(user, "PydentityRecoveryCodes", "RecoveryCodes", merged_codes)

    async def get_two_factor_enabled(self, user: TUser) -> bool:
        return user.two_factor_enabled

    async def set_two_factor_enabled(self, user: TUser, enabled: bool) -> None:
        user.two_factor_enabled = enabled

    def create_model_from_dict(self, **kwargs) -> TUser:
        return User(**kwargs)

    async def all(self) -> list[TUser]:
        return [u for u in self.db.Users.values()]

    async def create(self, user: TUser) -> IdentityResult:
        return IdentityResult.success()

    async def update(self, user: TUser) -> IdentityResult:
        return IdentityResult.success()

    async def delete(self, user: TUser) -> IdentityResult:
        return IdentityResult.success()

    async def find_by_id(self, user_id: str) -> Optional[TUser]:
        return self.db.Users.get(user_id, None)

    async def find_by_name(self, normalized_username: str) -> Optional[TUser]:
        for u in self.db.Users.values():
            if u.normalized_username == normalized_username:
                return u
        return None

    async def get_user_id(self, user: TUser) -> str:
        return user.id

    async def get_username(self, user: TUser) -> Optional[str]:
        return user.username

    async def set_username(self, user: TUser, username: Optional[str]) -> None:
        user.username = username

    async def get_normalized_username(self, user: TUser) -> Optional[str]:
        return user.normalized_username

    async def set_normalized_username(self, user: TUser, normalized_name: Optional[str]) -> None:
        user.normalized_username = normalized_name


@pytest.fixture
def db():
    return DB()


@pytest.fixture
def role_store(db) -> RoleStore:
    return RoleStore(db)


@pytest.fixture
def role_manager(role_store):
    return RoleManager(role_store, key_normalizer=UpperLookupNormalizer())


@pytest.fixture
def user_store(db) -> UserStore:
    return UserStore(db)


@pytest.fixture
def user_manager(user_store):
    return UserManager(user_store, key_normalizer=UpperLookupNormalizer())
