import logging

from fastapi import Form, Depends, Query, HTTPException
from fastapi.requests import Request
from pydantic import EmailStr, SecretStr, ValidationError
from starlette.responses import RedirectResponse

from example.fastapi.api.dependencies import EmailService, UserManager, SignInManager
from example.fastapi.api.v1.account._router import router


class RegisterInputModel:
    def __init__(
            self,
            email: EmailStr = Form(alias='email', validation_alias='email'),
            password: SecretStr = Form(alias='password', validation_alias='password'),
            confirm_password: SecretStr = Form(alias='confirmPassword', validation_alias='confirmPassword')
    ):
        self.email = email
        self.password = password
        self.confirm_password = confirm_password


@router.post('/register')
async def register(
        request: Request,
        form: RegisterInputModel = Depends(),
        user_manager: UserManager = Depends(),
        signin_manager: SignInManager = Depends(),
        email_service: EmailService = Depends()
):
    if form.password.get_secret_value() != form.confirm_password.get_secret_value():
        raise HTTPException(status_code=400, detail=["Passwords don't match."])

    user = user_manager.store.create_model_from_dict(
        email=form.email,
        username=form.email
    )

    result = await user_manager.create(user, form.password.get_secret_value())

    if result.succeeded:
        user_id = await user_manager.get_user_id(user)
        code = await user_manager.generate_email_confirmation_token(user)
        callback_url = request.url_for('confirm_email').include_query_params(
            userId=user_id,
            code=code
        )

        email_service.send(
            form.email,
            'Confirm your email',
            f"Please confirm your account by <a href='{callback_url}'>clicking here</a>."
        )

        if user_manager.options.signin.required_confirmed_account:
            logging.getLogger('Authentication').debug(
                request.url_for('register_confirmation').include_query_params(email=form.email)
            )
            return RedirectResponse(
                request.url_for('register_confirmation').include_query_params(email=form.email),
                status_code=303
            )
        else:
            await signin_manager.sign_in(user, is_persistent=False)

    raise HTTPException(status_code=400, detail=[err.description for err in result.errors])


@router.get('/register-confirmation')
async def register_confirmation(
        request: Request,
        email: EmailStr = Query(alias='email', validation_alias='email'),
        user_manager: UserManager = Depends()
):
    user = await user_manager.find_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail=f"Unable to load user with email '{email}'.")

    # Once you add a real email sender, you should remove this code that lets you confirm the account
    user_id = await user_manager.get_user_id(user)
    code = await user_manager.generate_email_confirmation_token(user)

    callback_url = request.url_for('confirm_email').include_query_params(userId=user_id, code=code)
    return callback_url
