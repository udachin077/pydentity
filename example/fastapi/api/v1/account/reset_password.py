from fastapi import Form, Query, Depends, HTTPException
from pydantic import EmailStr, SecretStr, ValidationError

from example.fastapi.api.dependencies import UserManager
from example.fastapi.api.v1.account._router import router


class ResetPasswordInputModel:
    def __init__(
            self,
            code: str = Form(alias='code', validation_alias='code'),
            email: EmailStr = Form(alias='email', validation_alias='email'),
            password: SecretStr = Form(alias='password', validation_alias='password'),
            confirm_password: SecretStr = Form(alias='confirmPassword', validation_alias='confirmPassword')
    ):
        self.code = code
        self.email = email
        self.password = password
        self.confirm_password = confirm_password


@router.post('/reset-password')
async def reset_password(
        form: ResetPasswordInputModel = Depends(),
        manager: UserManager = Depends(),
):
    if form.password.get_secret_value() != form.confirm_password.get_secret_value():
        raise HTTPException(status_code=400, detail=["Passwords don't match."])

    user = await manager.find_by_email(form.email)

    if not user:
        # Don't reveal that the user does not exist
        return

    await manager.reset_password(user, form.code, form.password.get_secret_value())
