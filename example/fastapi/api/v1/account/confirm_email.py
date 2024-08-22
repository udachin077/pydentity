import logging

from fastapi import Query, HTTPException, Depends

from example.fastapi.api.dependencies import UserManager, SignInManager
from example.fastapi.api.v1.account._router import router


@router.get('/confirm-email')
async def confirm_email(
        user_id: str = Query(alias='userId', validation_alias='userId'),
        code: str = Query(alias='code', validation_alias='code'),
        manager: UserManager = Depends()
):
    if not user_id or not code:
        pass

    user = await manager.find_by_id(user_id)
    if not user:
        logging.getLogger('Authentication').warning(f"Unable to load user with ID '{user_id}'.")
        return "Error confirming your email."

    result = await manager.confirm_email(user, code)
    return "Thank you for confirming your email." if result.succeeded else "Error confirming your email."


@router.get('/confirm-email-change')
async def confirm_email_change(
        user_id: str = Query(alias='userId', validation_alias='userId'),
        email: str = Query(alias='email', validation_alias='email'),
        code: str = Query(alias='code', validation_alias='code'),
        user_manager: UserManager = Depends(),
        signin_manager: SignInManager = Depends()
):
    user = await user_manager.find_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=404,
            detail=f"Unable to load user with ID '{user_id}'."
        )

    result = await user_manager.change_email(user, email, code)
    if not result.succeeded:
        raise HTTPException(
            status_code=400,
            detail="Error changing email."
        )

    # In our UI email and username are one and the same, so when we update the email we need to update the username.
    set_username_result = await user_manager.set_username(user, email)
    if not set_username_result.succeeded:
        raise HTTPException(
            status_code=400,
            detail="Error changing username."
        )

    await signin_manager.refresh_sign_in(user)
