<h1 align="center">Pydentity</h1>

## Install

```
pip install fastapi-pydentity[sqlalchemy]
```
or
```
pip install fastapi-pydentity[tortoise]
```

## Usage

```python

from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException
from pydantic import EmailStr, SecretStr

from pydentity import SignInManager, UserManager
from pydentity.abc.stores import IUserStore, IRoleStore
from pydentity.contrib.fastapi import PydentityBuilder, use_authentication, use_authorization
from pydentity.contrib.fastapi.authorization import authorize


class UserStore(..., IUserStore):
    ...


class RoleStore(IRoleStore):
    ...


builder = PydentityBuilder()
builder.add_default_identity(UserStore, RoleStore)
builder.add_authorization()
builder.build()

app = FastAPI()

use_authentication(app)
use_authorization(app)


class LoginInputModel:
    def __init__(
            self,
            email: EmailStr = Form(alias='email', validation_alias='email'),
            password: SecretStr = Form(alias='password', validation_alias='password'),
            remember_me: bool = Form(alias='rememberMe', validation_alias='rememberMe')
    ):
        self.email = email
        self.password = password
        self.remember_me = remember_me


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


@app.get("/users", dependencies=[authorize()])
async def get_users(user_manager: Annotated[UserManager, Depends()]):
    return [user.email for user in await user_manager.all()]
```