# noinspection SpellCheckingInspection
_ERROR_MESSAGES: dict[str, str] = {
    "DefaultError": "An unknown failure has occurred.",
    "DuplicateEmail": "Email '{0}' is already taken.",
    "DuplicateRoleName": "Role name '{0}' is already taken.",
    "DuplicateUserName": "Username '{0}' is already taken.",
    "InvalidDomain": "Emails from the specified domain '{0}' are prohibited.",
    "InvalidEmail": "Email '{0}' is invalid.",
    "InvalidRoleName": "Role name '{0}' is invalid.",
    "InvalidToken": "Invalid token.",
    "InvalidUserName": "Username '{0}' is invalid, can only contain letters or digits.",
    "LoginAlreadyAssociated": "A user with this login already exists.",
    "NoTokenProvider": "No IUserTwoFactorTokenProvider[TUser] named '{0}' is registered.",
    "NullSecurityStamp": "User security stamp cannot be null.",
    "PasswordMismatch": "Incorrect password.",
    "PasswordRequiresDigit": "Passwords must have at least one digit.",
    "PasswordRequiresLower": "Passwords must have at least one lowercase.",
    "PasswordRequiresNonAlphanumeric": "Passwords must have at least one non alphanumeric character.",
    "PasswordRequiresUniqueChars": "Passwords must use at least {0} different characters.",
    "PasswordRequiresUpper": "Passwords must have at least one uppercase.",
    "PasswordTooShort": "Passwords must be at least {0} characters.",
    "RecoveryCodeRedemptionFailed": "Recovery code redemption failed.",
    "RoleNotFound": "Role {0} does not exist.",
    "StoreNotIUserAuthenticationTokenStore": "Store does not implement IUserAuthenticationTokenStore[TUser].",
    "StoreNotIUserAuthenticatorKeyStore": "Store does not implement IUserAuthenticatorKeyStore<User>.",
    "StoreNotIUserClaimStore": "Store does not implement IUserClaimStore[TUser].",
    "StoreNotIUserConfirmationStore": "Store does not implement IUserConfirmationStore[TUser].",
    "StoreNotIUserEmailStore": "Store does not implement IUserEmailStore[TUser].",
    "StoreNotIUserLockoutStore": "Store does not implement IUserLockoutStore[TUser].",
    "StoreNotIUserLoginStore": "Store does not implement IUserLoginStore[TUser].",
    "StoreNotIUserPasswordStore": "Store does not implement IUserPasswordStore[TUser].",
    "StoreNotIUserPersonalDataStore": "Store does not implement IUserPersonalDataStore[TUser].",
    "StoreNotIUserPhoneNumberStore": "Store does not implement IUserPhoneNumberStore[TUser].",
    "StoreNotIUserRoleStore": "Store does not implement IUserRoleStore[TUser].",
    "StoreNotIUserSecurityStampStore": "Store does not implement IUserSecurityStampStore[TUser].",
    "StoreNotIUserTwoFactorRecoveryCodeStore": "Store does not implement IUserTwoFactorRecoveryCodeStore[TUser].",
    "StoreNotIUserTwoFactorStore": "Store does not implement IUserTwoFactorStore[TUser].",
    "UserAlreadyHasPassword": "User already has a password set.",
    "UserAlreadyInRole": "User already in role '{0}'.",
    "UserLockedOut": "User is locked out.",
    "UserLockoutNotEnabled": "Lockout is not enabled for this user.",
    "UserNameNotFound": "User {0} does not exist.",
    "UserNotInRole": "User is not in role '{0}'.",
}
