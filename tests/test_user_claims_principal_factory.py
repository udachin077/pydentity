from dataclasses import field, dataclass
from uuid import uuid4

import pytest

from pydentity import UserClaimsPrincipalFactory, IdentityOptions
from pydentity.security.claims import Claim, ClaimTypes


@dataclass
class MockUser:
    id: str = field(default=str(uuid4()))
    email: str = field(default='admin@email.com')
    username: str = field(default='username.com')
    phone_number: str = field(default='7777777')
    security_stamp: str = field(default=str(uuid4()))


class MockUserManager:
    def __init__(self):
        self.supports_user_email = True
        self.supports_user_security_stamp = True
        self.supports_user_claim = True
        self.supports_user_role = True

    async def get_user_id(self, user):
        return user.id

    async def get_username(self, user):
        return user.username

    async def get_email(self, user):
        return user.email

    async def get_security_stamp(self, user):
        return user.security_stamp

    async def get_claims(self, user):
        return [Claim(ClaimTypes.Country, 'London')]

    async def get_roles(self, user):
        return ['user', 'manager']


class MockRoleManager:
    def __init__(self):
        self.supports_role_claims = True

    async def find_by_name(self, name):
        return True

    async def get_claims(self, role):
        return [Claim('role_claim', 'wrtrfd')]


@pytest.mark.asyncio
async def test_create():
    factory = UserClaimsPrincipalFactory(
        MockUserManager(),
        MockRoleManager(),
        IdentityOptions()
    )
    principal = await factory.create(MockUser())
    assert principal.has_claim(ClaimTypes.Email, 'admin@email.com')
