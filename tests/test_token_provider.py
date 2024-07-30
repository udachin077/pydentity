from dataclasses import dataclass, field
from uuid import uuid4

import pytest

from pydentity import EmailTokenProvider, IdentityOptions


@dataclass
class MockUser:
    id: str = field(default=str(uuid4()))
    email: str = field(default='admin@email.com')
    phone_number: str = field(default='7777777')
    security_stamp: str = field(default=str(uuid4()))


class MockUserManager:
    def __init__(self):
        self.options = IdentityOptions()

    async def get_email(self, user):
        return user.email

    async def get_phone_number(self, user):
        return user.phone_number

    async def get_user_id(self, user):
        return user.id

    async def get_security_stamp(self, user):
        return user.security_stamp

    async def create_security_token(self, user):
        return user.security_stamp.encode()

    async def is_email_confirmed(self, user):
        return True


@pytest.mark.asyncio
async def test_generate():
    provider = EmailTokenProvider()
    token = await provider.generate(MockUserManager(), 'TOTP', MockUser())
    assert await provider.validate(MockUserManager(), 'TOTP', token, MockUser())
