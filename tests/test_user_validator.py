from uuid import uuid4

import pytest

from pydentity.user_validator import UserValidator


@pytest.mark.asyncio
@pytest.mark.parametrize("user_id, email, username, result", {
    (str(uuid4()), "alexandra@email.com", "alexandra", False,),  # email
    (str(uuid4()), "alexandra", "alexandra@email.com", False,),  # username
    (str(uuid4()), "username@email.com", "username@email.com", True,),
    (None, "alexandra@email.com", "alexandra@email.com", True,),
})
async def test_validate(user_manager, user_id, email, username, result):
    user = user_manager.store.create_model_from_dict(
        id=user_id or user_manager.store.db.USER_ALEXANDRA,
        email=email,
        normalized_email=email.upper(),
        username=username,
        normalized_username=username.upper(),
    )
    validation_result = await UserValidator().validate(user_manager, user)
    assert validation_result.succeeded is result
