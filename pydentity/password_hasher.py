from typing import Generic

from pydentity.abc import PasswordVerificationResult, IPasswordHasher
from pydentity.exc import ArgumentNoneException
from pydentity.types import TUser
from pydentity.utils import is_none_or_empty

__all__ = ('PasswordHasher', 'OldPasswordHasher',)


class PasswordHasher(IPasswordHasher[TUser], Generic[TUser]):
    """Implements the standard password hashing."""

    __slots__ = ('_hasher',)

    def __init__(self) -> None:
        from pwdlib import PasswordHash
        self._hasher = PasswordHash.recommended()

    def hash_password(self, user: TUser, password: str) -> str:
        if password is None:
            raise ArgumentNoneException('password')
        return self._hasher.hash(password)

    def verify_hashed_password(self, user: TUser, hashed_password: str, password: str) -> PasswordVerificationResult:
        if is_none_or_empty(password) or is_none_or_empty(hashed_password):
            return PasswordVerificationResult.Failed

        valid, _hash = self._hasher.verify_and_update(password, hashed_password)

        if valid:
            if _hash is not None:
                return PasswordVerificationResult.SuccessRehashNeeded
            return PasswordVerificationResult.Success
        return PasswordVerificationResult.Failed


class OldPasswordHasher(IPasswordHasher[TUser], Generic[TUser]):
    """Implements the standard password hashing."""

    __slots__ = ('_hasher',)

    def __init__(self) -> None:
        from passlib.context import CryptContext
        self._hasher = CryptContext(schemes=['bcrypt'])

    def hash_password(self, user: TUser, password: str) -> str:
        if password is None:
            raise ArgumentNoneException('password')
        return self._hasher.hash(password)

    def verify_hashed_password(self, user: TUser, hashed_password: str, password: str) -> PasswordVerificationResult:
        if is_none_or_empty(password) or is_none_or_empty(hashed_password):
            return PasswordVerificationResult.Failed

        if self._hasher.verify(password, hashed_password):
            if self._hasher.needs_update(hashed_password):
                return PasswordVerificationResult.SuccessRehashNeeded
            return PasswordVerificationResult.Success
        return PasswordVerificationResult.Failed
