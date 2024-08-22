from fastapi import Form, Depends, HTTPException
from fastapi.requests import Request
from pydantic import SecretStr, ValidationError

from example.fastapi.api.dependencies import UserManager, SignInManager
from example.fastapi.api.v1.account.manage._router import router


class ChangePasswordInputModel:
    def __init__(
            self,
            old_password: SecretStr = Form(alias='oldPassword', validation_alias='oldPassword'),
            new_password: SecretStr = Form(alias='newPassword', validation_alias='newPassword'),
            confirm_password: SecretStr = Form(alias='confirmPassword', validation_alias='confirmPassword')
    ):
        if new_password.get_secret_value() != confirm_password.get_secret_value():
            raise ValidationError("passwords don't match")

        self.old_password = old_password
        self.new_password = new_password
        self.confirm_password = confirm_password


@router.post('/change-password')
async def change_password(
        request: Request,
        form: ChangePasswordInputModel = Depends(),
        user_manager: UserManager = Depends(),
        signin_manager: SignInManager = Depends()
):
    # Need to use middleware for access to request.user
    user = await user_manager.get_user(request.user)

    if not user:
        raise HTTPException(
            status_code=404,
            detail=f"Unable to load user with ID '{await user_manager.get_user_id(user)}'."
        )

    change_password_result = await user_manager.change_password(
        user,
        form.old_password.get_secret_value(),
        form.new_password.get_secret_value()
    )

    if not change_password_result.succeeded:
        raise HTTPException(status_code=400, detail=[e.description for e in change_password_result.errors])

    await signin_manager.refresh_sign_in(user)
