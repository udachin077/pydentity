from fastapi import Form, Depends, HTTPException
from fastapi.requests import Request
from pydantic import EmailStr

from example.fastapi.api.dependencies import UserManager, EmailService
from example.fastapi.api.v1.account.manage._router import router


class ChangeEmailInputModel:
    def __init__(self, new_email: EmailStr = Form(alias='newEmail', validation_alias='newEmail')):
        self.new_email = new_email


@router.post('/change-email')
async def change_email(
        request: Request,
        form: ChangeEmailInputModel = Depends(),
        user_manager: UserManager = Depends(),
        email_service: EmailService = Depends()
):
    # Need to use middleware for access to request.user
    user = await user_manager.get_user(request.user)

    if not user:
        raise HTTPException(
            status_code=404,
            detail=f"Unable to load user with ID '{await user_manager.get_user_id(user)}'."
        )

    email = await user_manager.get_email(user)
    if form.new_email.casefold() != email.casefold():
        user_id = await user_manager.get_user_id(user)
        code = await user_manager.generate_change_email_token(user, form.new_email)

        callback_url = request.url_for('confirm_email_change').include_query_params(
            userId=user_id, email=form.new_email, code=code
        )

        email_service.send(
            form.new_email,
            'Confirm your email',
            f"Please confirm your account by <a href='{callback_url}'>clicking here</a>."
        )

    raise HTTPException(
        status_code=400,
        detail="Your email is unchanged."
    )


@router.post('/verification-email')
async def verification_email(
        request: Request,
        user_manager: UserManager = Depends(),
        email_service: EmailService = Depends()
):
    # Need to use middleware for access to request.user
    user = await user_manager.get_user(request.user)

    if not user:
        raise HTTPException(
            status_code=404,
            detail=f"Unable to load user with ID '{await user_manager.get_user_id(user)}'."
        )

    user_id = await user_manager.get_user_id(user)
    email = await user_manager.get_email(user)
    code = await user_manager.generate_email_confirmation_token(user)

    callback_url = request.url_for('confirm_email').include_query_params(
        userId=user_id, code=code
    )

    email_service.send(
        email,
        'Confirm your email',
        f"Please confirm your account by <a href='{callback_url}'>clicking here</a>."
    )

    return callback_url
