from example.fastapi.api.v1.account.manage._router import router

from example.fastapi.api.v1.account.manage.change_password import change_password
from example.fastapi.api.v1.account.manage.personal_data import delete_personal_data, download_personal_data
from example.fastapi.api.v1.account.manage.two_factor import (
    get_enable_authenticator,
    post_enable_authenticator,
    disable_2fa,
    reset_authenticator,
    generate_recovery_codes
)
from example.fastapi.api.v1.account.manage.email import verification_email, change_email
from example.fastapi.api.v1.account.manage.set_password import set_password
