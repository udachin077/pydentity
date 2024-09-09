<h1 align="center">Pydentity</h1>

## Install

```
pip install fastapi-pydentity
```

## Base usage

```python
import uuid
from typing import Annotated

from fastapi import FastAPI, Depends, Form, HTTPException
from pydantic import EmailStr, SecretStr

from pydentity import SignInManager, UserManager
from pydentity.abc.stores import IRoleStore, IUserPasswordStore, IUserEmailStore, IUserSecurityStampStore
from pydentity.contrib.fastapi import PydentityBuilder
from pydentity.types import UserProtokol

USERS_DB = {}


class User(UserProtokol):
    def __init__(self, email, username):
        self.id = str(uuid.uuid4())
        self.email = email
        self.username = username


class UserStore(IUserPasswordStore, IUserEmailStore, IUserSecurityStampStore):
    ...


class RoleStore(IRoleStore):
    ...


builder = PydentityBuilder()
builder.add_default_identity(UserStore, RoleStore)
builder.build()

app = FastAPI()


class RegisterInputModel:
    def __init__(
            self,
            email: EmailStr = Form(alias="email", validation_alias="email"),
            password: SecretStr = Form(alias="password", validation_alias="password"),
            confirm_password: SecretStr = Form(alias="confirmPassword", validation_alias='confirmPassword')
    ):
        self.email = email
        self.password = password
        self.confirm_password = confirm_password


class LoginInputModel:
    def __init__(
            self,
            email: EmailStr = Form(alias="email", validation_alias="email"),
            password: SecretStr = Form(alias="password", validation_alias="password"),
            remember_me: bool = Form(alias="rememberMe", validation_alias="rememberMe")
    ):
        self.email = email
        self.password = password
        self.remember_me = remember_me


@app.post("/register")
async def register(
        form: Annotated[RegisterInputModel, Depends()],
        user_manager: Annotated[UserManager, Depends()],
        signin_manager: Annotated[SignInManager, Depends()],
):
    if form.password.get_secret_value() != form.confirm_password.get_secret_value():
        raise HTTPException(status_code=400, detail=["Passwords don't match."])

    user = User(email=form.email, username=form.email)
    result = await user_manager.create(user, form.password.get_secret_value())

    if result.succeeded:
        await signin_manager.sign_in(user, is_persistent=False)
    else:
        raise HTTPException(status_code=400, detail=[err.description for err in result.errors])


@app.post("/login")
async def login(
        form: Annotated[LoginInputModel, Depends()],
        signin_manager: Annotated[SignInManager, Depends()],
):
    result = await signin_manager.password_sign_in(
        form.email,
        form.password.get_secret_value(),
        form.remember_me
    )

    user = await signin_manager.user_manager.find_by_email(form.email)

    if result.succeeded:
        return {"username": user.email}

    if result.requires_two_factor:
        return {"requiresTwoFactor": True}

    if result.is_locked_out:
        raise HTTPException(status_code=401, detail="Invalid login attempt.")

    raise HTTPException(status_code=401, detail="Invalid login attempt.")


@app.post("/logout")
async def logout(signin_manager: Annotated[SignInManager, Depends()]):
    await signin_manager.sign_out()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("__main__:app")
```

## Configure `IdentityOptions`

```python
def configure_options(options: IdentityOptions):
    options.signin.required_confirmed_account = False
    options.password.required_digit = False


builder = PydentityBuilder()
builder.add_default_identity(UserStore, RoleStore).configure_options(configure_options)
```

| Attribute         | Type                    | 
|-------------------|-------------------------|
| `claims_identity` | `ClaimsIdentityOptions` | 
| `lockout`         | `LockoutOptions`        | 
| `password`        | `PasswordOptions`       | 
| `signin`          | `SignInOptions`         | 
| `tokens`          | `TokenOptions`          | 
| `user`            | `UserOptions`           | 

### `LockoutOptions`

Options for configuring user lockout.

| Attribute                    | Type        | Description                                                                                                          | Default                |
|------------------------------|-------------|----------------------------------------------------------------------------------------------------------------------|------------------------|
| `allowed_for_new_user`       | `bool`      | Gets or sets a flag indicating whether a new user can be locked out.                                                 | `True`                 |
| `default_lockout_timespan`   | `timedelta` | Gets or sets the `timedelta` a user is locked out for when a lockout occurs.                                         | `timedelta(minutes=5)` |
| `max_failed_access_attempts` | `int`       | Gets or sets the number of failed access attempts allowed before a user is locked out, assuming lock out is enabled. | `5`                    |                                                                                        |             |

### `ClaimsIdentityOptions`

Options used to configure the claim types used for well known claims.

| Attribute                   | Type  | Description                                                        | Default                     |
|-----------------------------|-------|--------------------------------------------------------------------|-----------------------------|
| `role_claim_type`           | `str` | Gets or sets the `claim_types` used for a role claim.              | `ClaimTypes.Role`           |
| `username_claim_type`       | `str` | Gets or sets the `claim_types` used for a user claim.              | `ClaimTypes.Name`           |
| `user_id_claim_type`        | `str` | Gets or sets the `claim_types` used for the user identifier claim. | `ClaimTypes.NameIdentifier` |
| `email_claim_type`          | `str` | Gets or sets the `claim_types` used for the user email claim.      | `ClaimTypes.Email`          |
| `security_stamp_claim_type` | `str` | Gets or sets the `claim_types` for the security stamp claim.       | `ClaimTypes.SecurityStamp`  |

### PasswordOptions

Specifies options for password requirements.

| Attribute                   | Type   | Description                                                                            | Default |
|-----------------------------|--------|----------------------------------------------------------------------------------------|---------|
| `required_digit`            | `bool` | Gets or sets a flag indicating if passwords must contain a digit.                      | `True`  |
| `required_length`           | `int`  | Gets or sets the minimum length a password must be.                                    | `8`     |
| `required_unique_chars`     | `int`  | Gets or sets the minimum number of unique characters which a password must contain.    | `1`     |
| `required_lowercase`        | `bool` | Gets or sets a flag indicating if passwords must contain a lower case ASCII character. | `True`  |
| `required_uppercase`        | `bool` | Gets or sets a flag indicating if passwords must contain a upper case ASCII character. | `True`  |
| `required_non_alphanumeric` | `bool` | Gets or sets a flag indicating if passwords must contain a non-alphanumeric character. | `True`  |

### SignInOptions

Options for configuring sign-in.

| Attribute                         | Type   | Description                                                                                                  | Default |
|-----------------------------------|--------|--------------------------------------------------------------------------------------------------------------|---------|
| `required_confirmed_email`        | `bool` | Gets or sets a flag indicating whether a confirmed email address is required to sign in.                     | `False` |
| `required_confirmed_phone_number` | `bool` | Gets or sets a flag indicating whether a confirmed telephone number is required to sign in.                  | `False` |
| `required_confirmed_account`      | `bool` | Gets or sets a flag indicating whether a confirmed `IUserConfirmation[TUser]` account is required to sign in | `True`  |

### `TokenOptions`

Options for user tokens.

| Constants                         | Type  | Default         |
|-----------------------------------|-------|-----------------|
| `DEFAULT_PROVIDER`                | `str` | `Default`       |
| `DEFAULT_EMAIL_PROVIDER`          | `str` | `Email`         |
| `DEFAULT_PHONE_PROVIDER`          | `str` | `Phone`         |
| `DEFAULT_AUTHENTICATION_PROVIDER` | `str` | `Authenticator` |

| Attribute                                  | Type  | Description                                                                                        | Default                           |
|--------------------------------------------|-------|----------------------------------------------------------------------------------------------------|-----------------------------------|
| `authenticator_token_provider`             | `str` | Gets or sets the token provider used to validate two factor sign ins with an authenticator.        | `DEFAULT_AUTHENTICATION_PROVIDER` |
| `change_email_token_provider`              | `str` | Gets or sets the token provider used to generate tokens used in email change confirmation emails.  | `DEFAULT_EMAIL_PROVIDER`          |
| `change_phone_number_token_provider`       | `str` | Gets or sets the token provider used to generate tokens used when changing phone numbers.          | `DEFAULT_PHONE_PROVIDER`          |
| `email_confirmation_token_provider`        | `str` | Gets or sets the token provider used to generate tokens used in account confirmation emails.       | `DEFAULT_EMAIL_PROVIDER`          |
| `phone_number_confirmation_token_provider` | `str` | Gets or sets the token provider used to generate tokens used in account confirmation phone number. | `DEFAULT_PHONE_PROVIDER`          |
| `password_reset_token_provider`            | `str` | Gets or sets the token provider used to generate tokens used in password reset emails.             | `DEFAULT_PROVIDER`                |
| `totp_interval`                            | `int` | Gets or sets the totp interval in seconds.                                                         | `180`                             |

### `UserOptions`

Options for user validation.

| Attribute                     | Type            | Description                                                                                 | Default                                                              |
|-------------------------------|-----------------|---------------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| `allowed_username_characters` | `str`           | Gets or sets the list of allowed characters in the username used to validate user names.    | `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-_` |
| `require_unique_email`        | `bool`          | Gets or sets a flag indicating whether the application requires unique emails for its auth. | `True`                                                               |
| `allowed_email_domains`       | `Iterable[str]` | Gets or sets a list of available domains for email.                                         | `None`                                                               |

### `StoreOptions`

Used for store specific options.

| Attribute               | Type   | Description                                                                                                                                                                  | Default |
|-------------------------|--------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `protect_personal_data` | `bool` | If set to True, the store must protect all personally identifying data for a user. This will be enforced by requiring the store to implement ``IProtectedUserStore[TUser]``. | `False` |

## Logging

### Standard logger

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

Use `add_user_manager_logger`, `add_role_manager_logger` and `add_signin_manager_logger`.

```python
from pydentity.abc import ILogger
from pydentity.contrib.fastapi import PydentityBuilder


class UserManagerLogger(ILogger):
    def warning(self, message: str) -> None:
        pass

    def debug(self, message: str) -> None:
        pass

    def error(self, message: str) -> None:
        pass

    def info(self, message: str) -> None:
        pass


builder = PydentityBuilder()
builder.add_default_identity(UserStore, RoleStore).add_user_manager_logger(UserManagerLogger())
```
