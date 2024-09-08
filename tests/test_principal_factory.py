import pytest

from pydentity import UserClaimsPrincipalFactory, IdentityOptions
from pydentity.security.claims import ClaimTypes
from tests.conftest import MockUser


@pytest.mark.asyncio
async def test_create(user_manager, role_manager):
    factory = UserClaimsPrincipalFactory(
        user_manager,
        role_manager,
        IdentityOptions()
    )
    principal = await factory.create(MockUser())
    assert principal.has_claim(ClaimTypes.Email, 'john.doe@example.com')