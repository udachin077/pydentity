from pydentity.identity_error import IdentityError
from pydentity.resources import Resources


# noinspection PyPep8Naming
class IdentityErrorDescriber:
    """Service to enable localization for application facing identity errors."""

    __slots__ = ()

    @staticmethod
    def DefaultError():
        return IdentityError(
            code="DefaultError",
            description=Resources.DefaultError
        )

    @staticmethod
    def DuplicateEmail(email: str):
        return IdentityError(
            code="DuplicateEmail",
            description=Resources.DuplicateEmail.format(email)
        )

    @staticmethod
    def DuplicateRoleName(name: str):
        return IdentityError(
            code="DuplicateRoleName",
            description=Resources.DuplicateRoleName.format(name)
        )

    @staticmethod
    def DuplicateUserName(name: str):
        return IdentityError(
            code="DuplicateUserName",
            description=Resources.DuplicateUserName.format(name)
        )

    @staticmethod
    def InvalidEmail(email: str):
        return IdentityError(
            code="InvalidEmail",
            description=Resources.InvalidEmail.format(email)
        )

    @staticmethod
    def InvalidRoleName(name: str):
        return IdentityError(
            code="InvalidRoleName",
            description=Resources.InvalidRoleName.format(name)
        )

    @staticmethod
    def InvalidDomain(domain: str):
        return IdentityError(
            code="InvalidDomain",
            description=Resources.InvalidDomain.format(domain)
        )

    @staticmethod
    def InvalidToken():
        return IdentityError(
            code="InvalidToken",
            description=Resources.InvalidToken
        )

    @staticmethod
    def InvalidUserName(name: str):
        return IdentityError(
            code="InvalidUserName",
            description=Resources.InvalidUserName.format(name)
        )

    @staticmethod
    def LoginAlreadyAssociated():
        return IdentityError(
            code="InvalidUserName",
            description=Resources.LoginAlreadyAssociated
        )

    @staticmethod
    def NullSecurityStamp():
        return IdentityError(
            code="NullSecurityStamp",
            description=Resources.NullSecurityStamp
        )

    @staticmethod
    def PasswordMismatch():
        return IdentityError(
            code="PasswordMismatch",
            description=Resources.PasswordMismatch
        )

    @staticmethod
    def PasswordRequiresDigit():
        return IdentityError(
            code="PasswordRequiresDigit",
            description=Resources.PasswordRequiresDigit
        )

    @staticmethod
    def PasswordRequiresLower():
        return IdentityError(
            code="PasswordRequiresLower",
            description=Resources.PasswordRequiresLower
        )

    @staticmethod
    def PasswordRequiresNonAlphanumeric():
        return IdentityError(
            code="PasswordRequiresNonAlphanumeric",
            description=Resources.PasswordRequiresNonAlphanumeric
        )

    @staticmethod
    def PasswordRequiresUpper():
        return IdentityError(
            code="PasswordRequiresUpper",
            description=Resources.PasswordRequiresUpper
        )

    @staticmethod
    def PasswordTooShort(length: int):
        return IdentityError(
            code="PasswordTooShort",
            description=Resources.PasswordTooShort.format(length)
        )

    @staticmethod
    def PasswordRequiresUniqueChars(unique_chars: int):
        return IdentityError(
            code="PasswordRequiresUniqueChars",
            description=Resources.PasswordRequiresUniqueChars.format(unique_chars)
        )

    @staticmethod
    def RoleNotFound(name: str):
        return IdentityError(
            code="RoleNotFound",
            description=Resources.RoleNotFound.format(name)
        )

    @staticmethod
    def RecoveryCodeRedemptionFailed():
        return IdentityError(
            code="RecoveryCodeRedemptionFailed",
            description=Resources.RecoveryCodeRedemptionFailed
        )

    @staticmethod
    def UserAlreadyHasPassword():
        return IdentityError(
            code="UserAlreadyHasPassword",
            description=Resources.UserAlreadyHasPassword
        )

    @staticmethod
    def UserAlreadyInRole(name: str):
        return IdentityError(
            code="UserAlreadyInRole",
            description=Resources.UserAlreadyInRole.format(name)
        )

    @staticmethod
    def UserLockedOut():
        return IdentityError(
            code="UserLockedOut",
            description=Resources.UserLockedOut
        )

    @staticmethod
    def UserLockoutNotEnabled():
        return IdentityError(
            code="UserLockoutNotEnabled",
            description=Resources.UserLockoutNotEnabled
        )

    @staticmethod
    def UserNameNotFound(name: str):
        return IdentityError(
            code="UserNameNotFound",
            description=Resources.UserNameNotFound.format(name)
        )

    @staticmethod
    def UserNotInRole(name: str):
        return IdentityError(
            code="UserNotInRole",
            description=Resources.UserNotInRole.format(name)
        )
