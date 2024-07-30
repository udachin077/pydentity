from pydentity.abc import PasswordVerificationResult
from pydentity.password_hasher import OldPasswordHasher, PasswordHasher
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


def test_verify_hashed_old_password():
    password_hasher = OldPasswordHasher()
    hashed_password = password_hasher.hash_password(MockUser(), 'password')
    result = password_hasher.verify_hashed_password(MockUser(), hashed_password, 'password')
    assert result == PasswordVerificationResult.Success
    result = password_hasher.verify_hashed_password(MockUser(), hashed_password, 'p@ssword')
    assert result == PasswordVerificationResult.Failed
