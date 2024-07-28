from uuid import uuid4

import pytest

from pydentity.user_validator import UserValidator


@pytest.mark.asyncio
@pytest.mark.parametrize("email, username, result", {
    ("alexandra@email.com", "alexandra", False,),
    ("alexandra", "alexandra@email.com", False,),
    ("username@email.com", "username@email.com", True,),
    ("alexandra@email.com", "alexandra@email.com", True,),
})
async def test_validate(email, username, result, user_manager, session):
    user = user_manager.store.create_model_from_dict(
        email=email,
        normalized_email=email.upper(),
        username=username,
        normalized_username=username.upper()
    )
    validation_result = await UserValidator().validate(user_manager, user)
    assert validation_result.succeeded is result
