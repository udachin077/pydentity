import uuid
from typing import cast

import pytest

from pydentity import UserManager, IdentityOptions
from pydentity.token_providers import TotpSecurityStampBasedTokenProvider, AuthenticatorTokenProvider, \
    DataProtectorTokenProvider
from pydentity.token_providers.rfc6238service import generate_code
from pydentity.types import UserProtokol


class MockUser(UserProtokol):
    authenticator_key: str


class MockUserManager:
    def __init__(self, options):
        self.options = options

    @property
    def supports_user_security_stamp(self):
        return True

    async def create_security_token(self, user) -> bytes:
        return user.security_stamp.encode()

    async def get_user_id(self, user) -> str:
        return user.id

    async def get_authenticator_key(self, user) -> str:
        return user.authenticator_key

    async def get_security_stamp(self, user) -> str:
        return user.security_stamp


@pytest.fixture
def mock_user():
    user = MockUser()
    user.id = str(uuid.uuid4())
    user.security_stamp = str(uuid.uuid4())
    user.authenticator_key = str(uuid.uuid4())
    return user


@pytest.fixture(scope="session")
def manager():
    return cast(UserManager, MockUserManager(IdentityOptions()))


@pytest.mark.asyncio
async def test_totp_security_stamp_based_token_provider(manager, mock_user):
    provider = TotpSecurityStampBasedTokenProvider()
    assert await provider.can_generate_two_factor(manager, mock_user) is True
    token = await provider.generate(manager, "totp", mock_user)
    result = await provider.validate(manager, "totp", token, mock_user)
    assert result is True
    result = await provider.validate(manager, "fake", token, mock_user)
    assert result is False


@pytest.mark.asyncio
async def test_authenticator_token_provider(manager, mock_user):
    provider = AuthenticatorTokenProvider()
    assert await provider.can_generate_two_factor(manager, mock_user) is True
    token = await provider.generate(manager, "", mock_user)
    assert token == ""
    token = generate_code((await manager.get_authenticator_key(mock_user)).encode())
    result = await provider.validate(manager, "", token, mock_user)
    assert result is True


@pytest.mark.asyncio
async def test_data_protector_token_provider(manager, mock_user):
    provider = DataProtectorTokenProvider()
    assert await provider.can_generate_two_factor(manager, mock_user) is False
    token = await provider.generate(manager, "totp", mock_user)
    result = await provider.validate(manager, "totp", token, mock_user)
    assert result is True
    result = await provider.validate(manager, "fake", token, mock_user)
    assert result is False
