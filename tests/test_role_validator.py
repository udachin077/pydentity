import pytest

from pydentity import RoleValidator, RoleManager
from tests.conftest import Role


@pytest.fixture
def manager() -> RoleManager:
    pass


@pytest.mark.asyncio
@pytest.mark.parametrize("role, result", {
    (Role(), True,),
    (Role(id='unique_id_12345'), True,),
    (Role(name='user', normalized_name='USER'), True,),
    (Role(name='guest', normalized_name='GUEST'), True,),
})
async def test_validate(role, result, manager):
    validator = RoleValidator()
    validation_result = await validator.validate(manager, role)
    assert validation_result.succeeded is result
