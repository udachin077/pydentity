from typing import cast

import pytest

from pydentity import IdentityOptions, UserManager
from pydentity.validators import PasswordValidator


class MockUserManager:
    def __init__(self, options):
        self.options = options


@pytest.fixture
def manager():
    return cast(UserManager, MockUserManager(IdentityOptions()))


@pytest.mark.asyncio
@pytest.mark.parametrize("passwords,expected", [
    (("N;92V[FPGgRn<Z?^", "a?mR!;6Au3VMw>kC", "tLJ8)MFkG[x2*3V6d>W}&:",), True,),
    (("password", "user", "123password@",), False,)
])
async def test_validate(manager, passwords, expected):
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize("passwords,expected", [
    (("N;V[FPGgRn<Z?^", "a?mR!;AuVMw>kC", "tLJ)MFkG[x*Vd>W}&:",), True,),
])
async def test_validate_required_digit(manager, passwords, expected):
    manager.options.password.required_digit = False
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize("passwords,expected", [
    (("N;92V[FPGgRn<Z?^", "a?mR!;6Au3VMw>kC", "tLJ8)MFkG[x2*3V6d>W}&:",), True,),
    (("N;V[FP345GgZ?", "a?mR!;AuVv54k", "tLJ)kG345W}&:", "P@ssw0rd1"), False,),
])
async def test_validate_required_length(manager, passwords, expected):
    manager.options.password.required_length = 14
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize("passwords,expected", [
    (("N;92V[FPGgRn<Z?^", "a?mR!;6Au3VMw>kC", "tLJ8)MFkG[x2*3V6d>W}&:",), True,),
    (("V;V1VVVgVV", "R;AuVMw>kC", "tLJ)MFkG[x:", "P@ssw0rdP@ssw0rd"), False,),
])
async def test_validate_required_unique_chars(manager, passwords, expected):
    manager.options.password.required_unique_chars = 8
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize("passwords,expected", [
    (("N;92V[FPGgRn<Z?^", "a?mR!;6Au3VMw>kC", "tLJ8)MFkG[x2*3V6d>W}&:", "p@ssword1",), True,),
])
async def test_validate_required_uppercase(manager, passwords, expected):
    manager.options.password.required_uppercase = False
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize("passwords,expected", [
    (("N;92V[FPGR<Z?^", "?R!;6A3VM>kC", "TLJ8)MFKG[x2*3V6D>W}&:", "P@SSW0RD1",), True,),
])
async def test_validate_required_lowercase(manager, passwords, expected):
    manager.options.password.required_lowercase = False
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize("passwords,expected", [
    (("N92VFPGgRnZ", "amR6Au3VMwkC", "tLJ8MFkGx23V6dW", "Passw0rd1",), True,),
])
async def test_validate_required_lowercase(manager, passwords, expected):
    manager.options.password.required_non_alphanumeric = False
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors
