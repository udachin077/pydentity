from fastapi import Form, HTTPException, Depends
from fastapi.requests import Request
from pydantic import EmailStr

from example.fastapi.api.dependencies import UserManager, EmailService
from example.fastapi.api.v1.account._router import router


@router.post('/forgot-password')
async def forgot_password(
        request: Request,
        email: EmailStr = Form(alias='email', validation_alias='email'),
        manager: UserManager = Depends(),
        email_service: EmailService = Depends()
):
    user = await manager.find_by_email(email)

    if not user or not (await manager.is_email_confirmed(user)):
        return 'Please check your email to reset your password.'

    code = await manager.generate_password_reset_token(user)
    callback_url = request.url_for('reset_password').include_query_params(code=code)

    email_service.send(
        email,
        'Reset password',
        f"Please reset your password by <a href='{callback_url}'>clicking here</a>."
    )

    return callback_url
