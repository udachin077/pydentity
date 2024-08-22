from example.fastapi.api.v1.account._router import router
from example.fastapi.api.v1.account.manage import router as manage_router

from example.fastapi.api.v1.account.register import register, register_confirmation
from example.fastapi.api.v1.account.confirm_email import confirm_email, confirm_email_change
from example.fastapi.api.v1.account.forgot_password import forgot_password
from example.fastapi.api.v1.account.reset_password import reset_password
from example.fastapi.api.v1.account.login import login
from example.fastapi.api.v1.account.login_with_2fa import login_with_2fa
from example.fastapi.api.v1.account.login_with_recovery_code import login_with_recovery_code
from example.fastapi.api.v1.account.logout import logout

router.include_router(manage_router)
