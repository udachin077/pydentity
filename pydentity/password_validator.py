from typing import TYPE_CHECKING, Generic, Optional

from pydentity.exc import ArgumentNoneException
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.abc import IPasswordValidator
from pydentity.types import TUser
from pydentity.utils import is_none_or_empty

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager


def _is_lower(c: str) -> bool:
    return 'a' <= c <= 'z'


def _is_digit(c: str) -> bool:
    return '0' <= c <= '9'


def _is_upper(c: str) -> bool:
    return 'A' <= c <= 'Z'


def _is_letter_or_digit(c: str) -> bool:
    return _is_lower(c) or _is_upper(c) or _is_digit(c)


class PasswordValidator(IPasswordValidator[TUser], Generic[TUser]):
    """Provides the default password policy for Identity."""

    def __init__(self, errors: Optional[IdentityErrorDescriber] = None):
        """

        :param errors: The IdentityErrorDescriber used to provider error messages.
        """
        self._describer = errors or IdentityErrorDescriber()

    async def validate(self, manager: "UserManager[TUser]", password: str) -> IdentityResult:
        if manager is None:
            raise ArgumentNoneException("manager")
        if password is None:
            raise ArgumentNoneException("password")

        options = manager.options.Password
        errors = []

        if is_none_or_empty(password) or len(password) < options.REQUIRED_LENGTH:
            errors.append(self._describer.PasswordTooShort(options.REQUIRED_LENGTH))

        if options.REQUIRE_DIGIT and not any(_is_digit(c) for c in password):
            errors.append(self._describer.PasswordRequiresDigit())

        if options.REQUIRE_LOWERCASE and not any(_is_lower(c) for c in password):
            errors.append(self._describer.PasswordRequiresLower())

        if options.REQUIRE_UPPERCASE and not any(_is_upper(c) for c in password):
            errors.append(self._describer.PasswordRequiresUpper())

        if options.REQUIRE_NON_ALPHANUMERIC and all(_is_letter_or_digit(c) for c in password):
            errors.append(self._describer.PasswordRequiresNonAlphanumeric())

        if options.REQUIRED_UNIQUE_CHARS >= 1 and len(set(password)) < options.REQUIRED_UNIQUE_CHARS:
            errors.append(self._describer.PasswordRequiresUniqueChars(options.REQUIRED_UNIQUE_CHARS))

        if not errors:
            return IdentityResult.success()

        return IdentityResult.failed(*errors)
