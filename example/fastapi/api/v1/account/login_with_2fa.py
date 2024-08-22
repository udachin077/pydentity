import logging

from fastapi import Form, HTTPException, Depends
from fastapi.responses import RedirectResponse

from example.fastapi.api.dependencies import SignInManager
from example.fastapi.api.v1.account._router import router


class LoginWith2faInputModel:
    def __init__(
            self,
            two_factor_code: str = Form(alias='twoFactorCode', validation_alias='twoFactorCode'),
            remember_me: bool = Form(alias='rememberMe', validation_alias='rememberMe'),
            remember_machine: bool = Form(alias='rememberMachine', validation_alias='rememberMachine')
    ):
        self.two_factor_code = two_factor_code
        self.remember_me = remember_me
        self.remember_machine = remember_machine


@router.post('/login-with-2fa')
async def login_with_2fa(
        form: LoginWith2faInputModel = Depends(),
        signin_manager: SignInManager = Depends()
):
    user = await signin_manager.get_two_factor_authentication_user()

    if not user:
        raise HTTPException(status_code=400, detail='Unable to load two-factor authentication user.')

    result = await signin_manager.two_factor_authenticator_sign_in(
        form.two_factor_code,
        form.remember_me,
        form.remember_machine
    )

    if result.succeeded:
        return

    if result.is_locked_out:
        logging.getLogger('Authentication').warning("User account locked out.")
        return {
            "isLockedOut": True
        }

    raise HTTPException(status_code=401, detail='Invalid authenticator code.')
