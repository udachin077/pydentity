from pydentity import PasswordHasher
from pydentity.abc import PasswordVerificationResult
from pydentity.types import UserProtokol


class MockUser(UserProtokol):
    pass


def test_verify_hashed_password():
    password_hasher = PasswordHasher()
    hashed_password = password_hasher.hash_password(MockUser(), 'password')
    result = password_hasher.verify_hashed_password(MockUser(), hashed_password, 'password')
    assert result == PasswordVerificationResult.Success
    result = password_hasher.verify_hashed_password(MockUser(), hashed_password, 'p@ssword')
    assert result == PasswordVerificationResult.Failed
