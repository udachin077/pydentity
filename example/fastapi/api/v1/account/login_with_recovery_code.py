from fastapi import Form, HTTPException, Depends

from example.fastapi.api.dependencies import SignInManager
from example.fastapi.api.v1.account._router import router


class LoginWithRecoveryCodeInputModel:
    def __init__(self, recovery_code: str = Form(alias='recoveryCode', validation_alias='recoveryCode')):
        self.recovery_code = recovery_code


@router.post('/login-with-recovery-code')
async def login_with_recovery_code(
        form: LoginWithRecoveryCodeInputModel = Depends(),
        manager: SignInManager = Depends()
):
    user = await manager.get_two_factor_authentication_user()

    if not user:
        raise HTTPException(status_code=400, detail='Unable to load two-factor authentication user.')

    recovery_code = form.recovery_code.replace(' ', '')
    result = await manager.two_factor_recovery_code_sign_in(recovery_code)

    if result.is_locked_out:
        raise HTTPException(status_code=403, detail=str(result))

    if not result.succeeded:
        raise HTTPException(status_code=400, detail='Invalid authenticator code.')
