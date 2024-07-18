from uuid import uuid4

import pytest

from pydentity.role_validator import RoleValidator


@pytest.mark.asyncio
@pytest.mark.parametrize("role_id, name, result", {
    (str(uuid4()), "admin", False,),
    (str(uuid4()), "manager", False,),
    (str(uuid4()), "tester", True,),
    (None, "admin", True,),
})
async def test_validate(role_manager, role_id, name, result):
    user = role_manager.store.create_model_from_dict(
        id=role_id or role_manager.store.db.ROLE_ADMIN,
        name=name,
        normalized_name=name.upper(),
    )
    validation_result = await RoleValidator().validate(role_manager, user)
    assert validation_result.succeeded is result
