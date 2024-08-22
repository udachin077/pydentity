import base64

from fastapi import Depends, Form, HTTPException
from fastapi.requests import Request

from example.fastapi.api.dependencies import UserManager, SignInManager
from example.fastapi.api.v1.account.manage._router import router
from pydentity.utils import generate_totp_qrcode_uri


@router.get('/enable-authenticator')
async def get_enable_authenticator(
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

    key = await user_manager.get_authenticator_key(user)
    if not key:
        await user_manager.reset_authenticator_key(user)
        key = await user_manager.get_authenticator_key(user)

    email = await user_manager.get_email(user)

    # Generate QR code from uri in to frontend.
    return generate_totp_qrcode_uri(key, email, 'FastAPI.Pydentity.UI')


class Enable2faInputModel:
    def __init__(self, code: str = Form(alias='code', validation_alias='code')):
        self.code = code


@router.post('/enable-authenticator')
async def post_enable_authenticator(
        request: Request,
        form: Enable2faInputModel = Depends(),
        user_manager: UserManager = Depends()
):
    # Need to use middleware for access to request.user
    user = await user_manager.get_user(request.user)

    if not user:
        raise HTTPException(
            status_code=404,
            detail=f"Unable to load user with ID '{await user_manager.get_user_id(user)}'."
        )

    verification_code = form.code.replace(" ", "").replace("-", "")
    is_2fa_token_valid = await user_manager.verify_two_factor_token(
        user,
        user_manager.options.tokens.authenticator_token_provider,
        verification_code
    )
    if not is_2fa_token_valid:
        raise HTTPException(
            status_code=400,
            detail="Verification code is invalid."
        )

    await user_manager.set_two_factor_enabled(user, True)

    if (await user_manager.count_recovery_codes(user)) == 0:
        recovery_codes = await user_manager.generate_new_two_factor_recovery_codes(user, 10)
        return recovery_codes


@router.post('/disable-2fa')
async def disable_2fa(
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

    if not (await user_manager.get_two_factor_enabled(user)):
        raise HTTPException(
            status_code=400,
            detail="Cannot disable 2FA for user as it's not currently enabled."
        )

    if not (await user_manager.set_two_factor_enabled(user, False)).succeeded:
        raise HTTPException(
            status_code=400,
            detail="Unexpected error occurred disabling 2FA."
        )


@router.post('/reset-authenticator')
async def reset_authenticator(
        request: Request,
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

    await user_manager.set_two_factor_enabled(user, False)
    await user_manager.reset_authenticator_key(user)
    await signin_manager.refresh_sign_in(user)


@router.post('/generate-recovery-codes')
async def generate_recovery_codes(
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

    if not await user_manager.get_two_factor_enabled(user):
        raise HTTPException(
            status_code=400,
            detail="Cannot generate recovery codes for user as they do not have 2FA enabled."
        )

    recovery_codes = await user_manager.generate_new_two_factor_recovery_codes(user, 10)
    return recovery_codes
