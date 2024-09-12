from pydenticore.interfaces import PasswordVerificationResult
from pydenticore.hashers.password_hasher import Argon2PasswordHasher, BcryptPasswordHasher
from pydenticore.types import UserProtokol


class MockUser(UserProtokol):
    pass


def test_verify_hashed_argon2():
    password_hasher = Argon2PasswordHasher()
    hashed_password = password_hasher.hash_password(MockUser(), 'password')
    result = password_hasher.verify_hashed_password(MockUser(), hashed_password, 'password')
    assert result == PasswordVerificationResult.Success
    result = password_hasher.verify_hashed_password(MockUser(), hashed_password, 'p@ssword')
    assert result == PasswordVerificationResult.Failed


def test_verify_hashed_bcrypt():
    password_hasher = BcryptPasswordHasher()
    hashed_password = password_hasher.hash_password(MockUser(), 'password')
    result = password_hasher.verify_hashed_password(MockUser(), hashed_password, 'password')
    assert result == PasswordVerificationResult.Success
    result = password_hasher.verify_hashed_password(MockUser(), hashed_password, 'p@ssword')
    assert result == PasswordVerificationResult.Failed
