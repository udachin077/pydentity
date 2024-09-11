## class `IdentityOptions`

```python
from pydentity import IdentityOptions

options = IdentityOptions()
```

| Attribute         | Type                    | 
|-------------------|-------------------------|
| `claims_identity` | `ClaimsIdentityOptions` | 
| `lockout`         | `LockoutOptions`        | 
| `password`        | `PasswordOptions`       | 
| `signin`          | `SignInOptions`         | 
| `tokens`          | `TokenOptions`          | 
| `user`            | `UserOptions`           | 

### class `LockoutOptions`

Options for configuring user lockout.

| Attribute                    | Type        | Description                                                                                                          | Default                |
|------------------------------|-------------|----------------------------------------------------------------------------------------------------------------------|------------------------|
| `allowed_for_new_user`       | `bool`      | Gets or sets a flag indicating whether a new user can be locked out.                                                 | `True`                 |
| `default_lockout_timespan`   | `timedelta` | Gets or sets the `timedelta` a user is locked out for when a lockout occurs.                                         | `timedelta(minutes=5)` |
| `max_failed_access_attempts` | `int`       | Gets or sets the number of failed access attempts allowed before a user is locked out, assuming lock out is enabled. | `5`                    |                                                                                        |             |

### class `ClaimsIdentityOptions`

Options used to configure the claim types used for well known claims.

| Attribute                   | Type  | Description                                                        | Default                     |
|-----------------------------|-------|--------------------------------------------------------------------|-----------------------------|
| `role_claim_type`           | `str` | Gets or sets the `claim_types` used for a role claim.              | `ClaimTypes.Role`           |
| `username_claim_type`       | `str` | Gets or sets the `claim_types` used for a user claim.              | `ClaimTypes.Name`           |
| `user_id_claim_type`        | `str` | Gets or sets the `claim_types` used for the user identifier claim. | `ClaimTypes.NameIdentifier` |
| `email_claim_type`          | `str` | Gets or sets the `claim_types` used for the user email claim.      | `ClaimTypes.Email`          |
| `security_stamp_claim_type` | `str` | Gets or sets the `claim_types` for the security stamp claim.       | `ClaimTypes.SecurityStamp`  |

### class `PasswordOptions`

Specifies options for password requirements.

| Attribute                   | Type   | Description                                                                            | Default |
|-----------------------------|--------|----------------------------------------------------------------------------------------|---------|
| `required_digit`            | `bool` | Gets or sets a flag indicating if passwords must contain a digit.                      | `True`  |
| `required_length`           | `int`  | Gets or sets the minimum length a password must be.                                    | `8`     |
| `required_unique_chars`     | `int`  | Gets or sets the minimum number of unique characters which a password must contain.    | `1`     |
| `required_lowercase`        | `bool` | Gets or sets a flag indicating if passwords must contain a lower case ASCII character. | `True`  |
| `required_uppercase`        | `bool` | Gets or sets a flag indicating if passwords must contain a upper case ASCII character. | `True`  |
| `required_non_alphanumeric` | `bool` | Gets or sets a flag indicating if passwords must contain a non-alphanumeric character. | `True`  |

### class `SignInOptions`

Options for configuring sign-in.

| Attribute                         | Type   | Description                                                                                                  | Default |
|-----------------------------------|--------|--------------------------------------------------------------------------------------------------------------|---------|
| `required_confirmed_email`        | `bool` | Gets or sets a flag indicating whether a confirmed email address is required to sign in.                     | `False` |
| `required_confirmed_phone_number` | `bool` | Gets or sets a flag indicating whether a confirmed telephone number is required to sign in.                  | `False` |
| `required_confirmed_account`      | `bool` | Gets or sets a flag indicating whether a confirmed `IUserConfirmation[TUser]` account is required to sign in | `True`  |

### class `TokenOptions`

Options for user tokens.

| Constants                         | Type  | Default         |
|-----------------------------------|-------|-----------------|
| `DEFAULT_PROVIDER`                | `str` | `Default`       |
| `DEFAULT_EMAIL_PROVIDER`          | `str` | `Email`         |
| `DEFAULT_PHONE_PROVIDER`          | `str` | `Phone`         |
| `DEFAULT_AUTHENTICATION_PROVIDER` | `str` | `Authenticator` |

| Attribute                                  | Type                                            | Description                                                                                        | Default                           |
|--------------------------------------------|-------------------------------------------------|----------------------------------------------------------------------------------------------------|-----------------------------------|
| `authenticator_token_provider`             | `str`                                           | Gets or sets the token provider used to validate two factor sign ins with an authenticator.        | `DEFAULT_AUTHENTICATION_PROVIDER` |
| `change_email_token_provider`              | `str`                                           | Gets or sets the token provider used to generate tokens used in email change confirmation emails.  | `DEFAULT_EMAIL_PROVIDER`          |
| `change_phone_number_token_provider`       | `str`                                           | Gets or sets the token provider used to generate tokens used when changing phone numbers.          | `DEFAULT_PHONE_PROVIDER`          |
| `email_confirmation_token_provider`        | `str`                                           | Gets or sets the token provider used to generate tokens used in account confirmation emails.       | `DEFAULT_EMAIL_PROVIDER`          |
| `phone_number_confirmation_token_provider` | `str`                                           | Gets or sets the token provider used to generate tokens used in account confirmation phone number. | `DEFAULT_PHONE_PROVIDER`          |
| `password_reset_token_provider`            | `str`                                           | Gets or sets the token provider used to generate tokens used in password reset emails.             | `DEFAULT_PROVIDER`                |
| `totp_interval`                            | `int`                                           | Gets or sets the totp interval in seconds.                                                         | `180`                             |
| `provider_map`                             | `dict[str, IUserTwoFactorTokenProvider[TUser]]` |                                                                                                    | `{}`                              |

### class `UserOptions`

Options for user validation.

| Attribute                     | Type            | Description                                                                                 | Default                                                              |
|-------------------------------|-----------------|---------------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| `allowed_username_characters` | `str`           | Gets or sets the list of allowed characters in the username used to validate user names.    | `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-_` |
| `require_unique_email`        | `bool`          | Gets or sets a flag indicating whether the application requires unique emails for its auth. | `True`                                                               |
| `allowed_email_domains`       | `Iterable[str]` | Gets or sets a list of available domains for email.                                         | `None`                                                               |

## Validators

```python
from pydentity import UserValidator, PasswordValidator, RoleValidator, UserManager, RoleManager

user_manager = UserManager(
    ...,
    user_validators=[UserValidator()],
    password_validators=[PasswordValidator()],
)
role_manager = RoleManager(
    ...,
    role_validators=[RoleValidator()],
)
```

| Validator           | Type                        |
|---------------------|-----------------------------|
| `UserValidator`     | `IUserValidator[TUser]`     | 
| `PasswordValidator` | `IPasswordValidator[TUser]` | 
| `RoleValidator`     | `IRoleValidator[TRole]`     | 

### Custom validators

```python
from pydentity import IdentityResult, UserManager, RoleManager
from pydentity.abc import IUserValidator, IPasswordValidator, IRoleValidator
from pydentity.types import TUser, TRole


class CustomUserValidator(IUserValidator):
    async def validate(self, manager: UserManager, user: TUser) -> IdentityResult:
        ...


class CustomPasswordValidator(IPasswordValidator):
    async def validate(self, manager: UserManager, password: str) -> IdentityResult:
        ...


class CustomRoleValidator(IRoleValidator):
    async def validate(self, manager: RoleManager, role: TRole) -> IdentityResult:
        ...


user_manager = UserManager(
    ...,
    user_validators=[CustomUserValidator()],
    password_validators=[CustomPasswordValidator()],
)
role_manager = RoleManager(
    ...,
    role_validators=[CustomRoleValidator()],
)
```

## Password hashers

Password hasher uses `pwdlib`.

```python
from pydentity import Argon2PasswordHasher, UserManager

user_manager = UserManager(
    ...,
    password_hasher=Argon2PasswordHasher()
)
```

| Hasher                 | Default hasher |  
|------------------------|----------------|
| `PasswordHasher`       | None           |     
| `BcryptPasswordHasher` | BcryptHasher   | 
| `Argon2PasswordHasher` | Argon2Hasher   |

### Custom password hasher

```python
from pydentity import UserManager
from pydentity.abc import IPasswordHasher, PasswordVerificationResult
from pydentity.types import TUser


class CustomPasswordHasher(IPasswordHasher):
    def hash_password(self, user: TUser, password: str) -> str:
        ...

    def verify_hashed_password(self, user: TUser, hashed_password: str, password: str) -> PasswordVerificationResult:
        ...


user_manager = UserManager(
    ...,
    password_hasher=CustomPasswordHasher()
)
```

## Token providers

Tokens are used to verify mail, phone, and two-factor authentication.

`TotpSecurityStampBasedTokenProvider` uses `pyotp`.

| Provider                              | Type                                         |
|---------------------------------------|----------------------------------------------|
| `TotpSecurityStampBasedTokenProvider` | `IUserTwoFactorTokenProvider[TUser]`         |
| `EmailTokenProvider`                  | `TotpSecurityStampBasedTokenProvider[TUser]` |
| `PhoneNumberTokenProvider`            | `TotpSecurityStampBasedTokenProvider[TUser]` |
| `AuthenticatorTokenProvider`          | `IUserTwoFactorTokenProvider[TUser]`         |
| `DataProtectorTokenProvider`          | `IUserTwoFactorTokenProvider[TUser]`         |

```python
from pydentity import IdentityOptions, EmailTokenProvider, AuthenticatorTokenProvider, DataProtectorTokenProvider

options = IdentityOptions()
options.tokens.provider_map[options.tokens.email_confirmation_token_provider] = EmailTokenProvider()
options.tokens.provider_map[options.tokens.change_email_token_provider] = EmailTokenProvider()
options.tokens.provider_map[options.tokens.authenticator_token_provider] = AuthenticatorTokenProvider()
options.tokens.provider_map["MyTokenProvider"] = DataProtectorTokenProvider()
```

## Logging

Current pydentity has three loggers: `pydentity.user_manager`, `pydentity.role_manager` and `pydentity.signin_manager`.

```python
import logging
import sys

fmt = logging.Formatter(
    fmt="%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG)
sh.setFormatter(fmt)

user_manager_logger = logging.getLogger("pydentity.user_manager")
user_manager_logger.setLevel(logging.DEBUG)
user_manager_logger.addHandler(sh)

role_manager_logger = logging.getLogger("pydentity.role_manager")
role_manager_logger.setLevel(logging.DEBUG)
role_manager_logger.addHandler(sh)

sign_in_manager_logger = logging.getLogger("pydentity.signin_manager")
sign_in_manager_logger.setLevel(logging.DEBUG)
sign_in_manager_logger.addHandler(sh)
```

### Custom logger

```python
from pydentity.abc import ILogger
from pydentity import UserManager


class UserManagerLogger(ILogger):
    def warning(self, message: str) -> None:
        pass

    def debug(self, message: str) -> None:
        pass

    def error(self, message: str) -> None:
        pass

    def info(self, message: str) -> None:
        pass


user_manager = UserManager(..., logger=UserManagerLogger())
```

