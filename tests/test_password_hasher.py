import pytest

from pydentity.hashers import BcryptPasswordHasher, Argon2PasswordHasher
from pydentity.interfaces import PasswordVerificationResult
from pydentity.types import UserProtokol


class MockUser(UserProtokol):
    pass


@pytest.fixture
def mock_user():
    return MockUser()


passwords = ["P@ssw0rd", "SecretPassword"]


@pytest.mark.parametrize("password", passwords)
def test_bcrypt_password_hasher(password, mock_user):
    hasher = BcryptPasswordHasher()
    pwd_hash = hasher.hash_password(mock_user, password)
    assert password != pwd_hash
    result = hasher.verify_hashed_password(mock_user, pwd_hash, password)
    assert result == PasswordVerificationResult.Success


@pytest.mark.parametrize("password", passwords)
def test_argon2password_hasher(password, mock_user):
    hasher = Argon2PasswordHasher()
    pwd_hash = hasher.hash_password(mock_user, password)
    assert password != pwd_hash
    result = hasher.verify_hashed_password(mock_user, pwd_hash, password)
    assert result == PasswordVerificationResult.Success
