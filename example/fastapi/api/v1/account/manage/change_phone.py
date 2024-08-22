from fastapi import Form, Depends, HTTPException
from fastapi.requests import Request

from example.fastapi.api.dependencies import UserManager, SignInManager
from example.fastapi.api.v1.account.manage._router import router


class ChangePhoneNumberInputModel:
    def __init__(self, phone_number: str = Form(alias='phoneNumber', validation_alias='phoneNumber')):
        self.phone_number = phone_number


@router.post('/change-phone')
async def change_phone(
        request: Request,
        form: ChangePhoneNumberInputModel = Depends(),
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

    phone_number = await user_manager.get_phone_number(user)
    if form.phone_number != phone_number:
        result = await user_manager.set_phone_number(user, form.phone_number)
        if not result.succeeded:
            raise HTTPException(
                status_code=400,
                detail="Unexpected error when trying to set phone number."
            )

    await signin_manager.refresh_sign_in(user)
    return "Your profile has been updated."
