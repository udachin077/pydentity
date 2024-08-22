from fastapi import Depends

from example.fastapi.api.dependencies import SignInManager
from example.fastapi.api.v1.account._router import router


@router.post('/logout')
async def logout(signin_manager: SignInManager = Depends()):
    await signin_manager.sign_out()
