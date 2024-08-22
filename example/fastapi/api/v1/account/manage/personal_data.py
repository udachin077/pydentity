import json

from fastapi import Depends, Form, HTTPException
from fastapi.requests import Request
from fastapi.responses import Response
from pydantic import SecretStr

from example.fastapi.api.dependencies import UserManager, SignInManager
from example.fastapi.api.v1.account.manage._router import router


class DeletePersonalDataInputModel:
    def __init__(self, password: SecretStr = Form(alias='password', validate_alias='password')):
        self.password = password


@router.post('/delete')
async def delete_personal_data(
        request: Request,
        form: DeletePersonalDataInputModel = Depends(),
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

    if await user_manager.has_password(user):
        if not await user_manager.check_password(user, form.password.get_secret_value()):
            raise HTTPException(status_code=400, detail="Incorrect password.")

    result = await user_manager.delete(user)
    if not result.succeeded:
        raise HTTPException(status_code=400, detail="Unexpected error occurred deleting user.")

    await signin_manager.sign_out()


@router.get('/download-personal-data')
async def download_personal_data(
        request: Request,
        user_manager: UserManager = Depends()
):
    # Need to use middleware for access to request.user
    user = await user_manager.get_user(request.user)

    if not user:
        raise HTTPException(
            status_code=404,
            detail=f"Unable to load user with ID '{await user_manager.get_user_id(user)}'."
        )

    personal_data = user_manager.get_personal_data(user)

    logins = await user_manager.get_logins(user)
    for l in logins:
        personal_data.update({f"{l.login_provider} external login provider key": l.provider_key})

    personal_data.update({'authenticator_key': await user_manager.get_authenticator_key(user)})

    response = Response(content=json.dumps(personal_data))
    response.headers["Content-Disposition"] = "attachment; filename=personal_data.json"
    response.headers["Content-Type"] = "application/json"
    return response
