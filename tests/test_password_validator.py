from typing import cast

import pytest

from pydentity import UserManager
from pydentity.identity_options import IdentityOptions
from pydentity.password_validator import PasswordValidator


class MockUserManager:
    def __init__(self):
        self.options = IdentityOptions()


@pytest.fixture
def user_manager() -> UserManager:
    return cast(UserManager, MockUserManager())


@pytest.fixture
def validator():
    return PasswordValidator()


@pytest.fixture
def options():
    options = IdentityOptions()
    options.password.required_digit = False
    options.password.required_length = 1
    options.password.required_unique_chars = 1
    options.password.required_lowercase = False
    options.password.required_non_alphanumeric = False
    options.password.required_uppercase = False
    return options


@pytest.mark.asyncio
@pytest.mark.parametrize("password, result", {
    ("P@ssw0rd", True,),
    ("P@ssword", False,),
})
async def test_validate_require_digit(password, result, user_manager, validator, options):
    user_manager.options = options
    user_manager.options.password.required_digit = True
    validation_result = await validator.validate(user_manager, password)
    assert validation_result.succeeded is result


@pytest.mark.asyncio
@pytest.mark.parametrize("password, result", {
    ("P@ssw0rd", False,),
    ("password_length", True,),
})
async def test_validate_require_length(password, result, user_manager, validator, options):
    user_manager.options = options
    user_manager.options.password.required_length = 10
    validation_result = await validator.validate(user_manager, password)
    assert validation_result.succeeded is result


@pytest.mark.asyncio
@pytest.mark.parametrize("password, result", {
    ("P@ssw0rd", False,),
    ("abcdefghijklmn", True,),
})
async def test_validate_require_unique_chars(password, result, user_manager, validator, options):
    user_manager.options = options
    user_manager.options.password.required_unique_chars = 8
    validation_result = await validator.validate(user_manager, password)
    assert validation_result.succeeded is result


@pytest.mark.asyncio
@pytest.mark.parametrize("password, result", {
    ("P@ssw0rd", True,),
    ("abcdefghijklmn", True,),
    ("7@ABCDEFGHIJ", False,),
})
async def test_validate_require_lowercase(password, result, user_manager, validator, options):
    user_manager.options = options
    user_manager.options.password.required_lowercase = True
    validation_result = await validator.validate(user_manager, password)
    assert validation_result.succeeded is result


@pytest.mark.asyncio
@pytest.mark.parametrize("password, result", {
    ("P@ssw0rd", True,),
    ("7@ABCDEFGHIJ", True,),
    ("abcdefghijklmn", False,),
})
async def test_validate_require_uppercase(password, result, user_manager, validator, options):
    user_manager.options = options
    user_manager.options.password.required_uppercase = True
    validation_result = await validator.validate(user_manager, password)
    assert validation_result.succeeded is result


@pytest.mark.asyncio
@pytest.mark.parametrize("password, result", {
    ("P@ssw0rd", True,),
    ("Passw0rd", False,),
})
async def test_validate_require_non_alphanumeric(password, result, user_manager, validator, options):
    user_manager.options = options
    user_manager.options.password.required_non_alphanumeric = True
    validation_result = await validator.validate(user_manager, password)
    assert validation_result.succeeded is result
