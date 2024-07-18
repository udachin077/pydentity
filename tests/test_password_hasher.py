import pytest

from pydentity.password_hasher import PasswordHasher, PasswordVerificationResult
from tests.conftest import User


@pytest.mark.parametrize("pwd_1,pwd_2,user,result", {
    ("password", "password", User, PasswordVerificationResult.Success,),
    ("password", "invalid_password", User, PasswordVerificationResult.Failed,),
})
def test_password_hasher_verify_hashed_password(pwd_1, pwd_2, user, result):
    hasher = PasswordHasher()
    hashed_password_1 = hasher.hash_password(user, pwd_1)
    hashed_password_2 = hasher.hash_password(user, pwd_2)
    assert hasher.verify_hashed_password(user, hashed_password_1, pwd_2) == result
    assert hasher.verify_hashed_password(user, hashed_password_2, pwd_1) == result
