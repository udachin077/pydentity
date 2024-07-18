import pytest

from pydentity.identity_options import IdentityOptions
from pydentity.password_validator import PasswordValidator


@pytest.fixture
def validator():
    return PasswordValidator()


@pytest.fixture
def options():
    options = IdentityOptions()
    options.Password.REQUIRE_DIGIT = False
    options.Password.REQUIRED_LENGTH = 1
    options.Password.REQUIRED_UNIQUE_CHARS = 1
    options.Password.REQUIRE_LOWERCASE = False
    options.Password.REQUIRE_NON_ALPHANUMERIC = False
    options.Password.REQUIRE_UPPERCASE = False
    return options


@pytest.mark.asyncio
@pytest.mark.parametrize("password, result", {
    ("P@ssw0rd", True,),
    ("P@ssword", False,),
})
async def test_validate_require_digit(password, result, user_manager, validator, options):
    user_manager.options = options
    user_manager.options.Password.REQUIRE_DIGIT = True
    validation_result = await validator.validate(user_manager, password)
    assert validation_result.succeeded is result


@pytest.mark.asyncio
@pytest.mark.parametrize("password, result", {
    ("P@ssw0rd", False,),
    ("password_length", True,),
})
async def test_validate_require_length(password, result, user_manager, validator, options):
    user_manager.options = options
    user_manager.options.Password.REQUIRED_LENGTH = 10
    validation_result = await validator.validate(user_manager, password)
    assert validation_result.succeeded is result


@pytest.mark.asyncio
@pytest.mark.parametrize("password, result", {
    ("P@ssw0rd", False,),
    ("abcdefghijklmn", True,),
})
async def test_validate_require_unique_chars(password, result, user_manager, validator, options):
    user_manager.options = options
    user_manager.options.Password.REQUIRED_UNIQUE_CHARS = 8
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
    user_manager.options.Password.REQUIRE_LOWERCASE = True
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
    user_manager.options.Password.REQUIRE_UPPERCASE = True
    validation_result = await validator.validate(user_manager, password)
    assert validation_result.succeeded is result


@pytest.mark.asyncio
@pytest.mark.parametrize("password, result", {
    ("P@ssw0rd", True,),
    ("Passw0rd", False,),
})
async def test_validate_require_non_alphanumeric(password, result, user_manager, validator, options):
    user_manager.options = options
    user_manager.options.Password.REQUIRE_NON_ALPHANUMERIC = True
    validation_result = await validator.validate(user_manager, password)
    assert validation_result.succeeded is result
