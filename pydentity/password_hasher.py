from typing import Generic

from pydentity.abc import PasswordVerificationResult, IPasswordHasher
from pydentity.exc import ArgumentNoneException
from pydentity.types import TUser
from pydentity.utils import is_none_or_empty


class PasswordHasher(IPasswordHasher[TUser], Generic[TUser]):
    """Implements the standard password hashing."""

    def __init__(self):
        from passlib.context import CryptContext

        self._crypt_context = CryptContext(schemes=["bcrypt"])

    def hash_password(self, user: TUser, password: str) -> str:
        if password is None:
            raise ArgumentNoneException("password")

        return self._crypt_context.hash(password)

    def verify_hashed_password(self, user: TUser, hashed_password: str, password: str) -> PasswordVerificationResult:
        if is_none_or_empty(password) or is_none_or_empty(hashed_password):
            return PasswordVerificationResult.Failed

        if self._crypt_context.verify(password, hashed_password):
            if self._crypt_context.needs_update(hashed_password):
                return PasswordVerificationResult.SuccessRehashNeeded

            return PasswordVerificationResult.Success

        return PasswordVerificationResult.Failed
