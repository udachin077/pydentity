import logging

from fastapi import Form, Depends, HTTPException
from pydantic import EmailStr, SecretStr

from example.fastapi.api.dependencies import SignInManager
from example.fastapi.api.v1.account._router import router


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


@router.post('/login')
async def login(
        form: LoginInputModel = Depends(),
        signin_manager: SignInManager = Depends(),
):
    result = await signin_manager.password_sign_in(
        form.email,
        form.password.get_secret_value(),
        form.remember_me
    )

    user = await signin_manager.user_manager.find_by_email(form.email)

    if result.succeeded:
        return {
            'username': user.username
        }

    if result.requires_two_factor:
        return {
            "requiresTwoFactor": True
        }

    if result.is_locked_out:
        logging.getLogger('Authentication').warning("User account locked out.")
        raise HTTPException(status_code=401, detail='Invalid login attempt.')

    raise HTTPException(status_code=401, detail='Invalid login attempt.')
