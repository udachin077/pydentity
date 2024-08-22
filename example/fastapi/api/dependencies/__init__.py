from fastapi import Depends
from pydentity_db_sqlalchemy.stores import UserStore, RoleStore
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from pydentity import (
    UserManager as UM,
    RoleManager as RM,
    PasswordValidator as PV,
    UserValidator as UV,
    RoleValidator as RV,
    IdentityOptions as IO,
    DefaultUserConfirmation as DUC,
    UpperLookupNormalizer as ULN,
    UserClaimsPrincipalFactory as UCPF,
    TotpSecurityStampBasedTokenProvider,
    EmailTokenProvider,
    PhoneNumberTokenProvider,
    SignInManager as SIM
)
from pydentity.contrib.fastapi.authentication.provider import AuthenticationSchemeProvider
from pydentity.contrib.fastapi.authentication.scheme import AuthenticationScheme
from pydentity.contrib.fastapi import HttpContext
from pydentity.contrib.fastapi.authentication.cookie import CookieAuthenticationHandler
from pydentity.identity_constants import IdentityConstants
from pydentity.token_provider import AuthenticatorTokenProvider


def get_engine():
    return create_async_engine('sqlite+aiosqlite:///test.db', echo=True)


def get_async_session_maker(engine=Depends(get_engine)):
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_session(async_session_maker=Depends(get_async_session_maker)):
    async with async_session_maker() as sn:
        yield sn


def get_user_store(session=Depends(get_session)):
    return UserStore(session)


def get_role_store(session=Depends(get_session)):
    return RoleStore(session)


def get_password_validators():
    return (PV(),)


def get_user_validators():
    return (UV(),)


def get_role_validators():
    return (RV(),)


def get_user_confirmation():
    return DUC()


opt = IO()
email_token_provider = EmailTokenProvider()
phone_token_provider = PhoneNumberTokenProvider()
default_token_provider = TotpSecurityStampBasedTokenProvider()
opt.tokens.provider_map[opt.tokens.password_reset_token_provider] = default_token_provider
opt.tokens.provider_map[opt.tokens.email_confirmation_token_provider] = email_token_provider
opt.tokens.provider_map[opt.tokens.change_email_token_provider] = email_token_provider
opt.tokens.provider_map[opt.tokens.phone_number_confirmation_token_provider] = phone_token_provider
opt.tokens.provider_map[opt.tokens.change_phone_number_token_provider] = phone_token_provider
opt.tokens.provider_map[opt.tokens.authenticator_token_provider] = AuthenticatorTokenProvider()


class UserManager(UM):
    def __init__(
            self,
            store=Depends(get_user_store),
            key_normalizer=Depends(ULN),
            password_validators=Depends(get_password_validators),
            user_validators=Depends(get_user_validators),
    ):
        super().__init__(
            store,
            key_normalizer=key_normalizer,
            password_validators=password_validators,
            user_validators=user_validators,
            options=opt
        )


class RoleManager(RM):
    def __init__(
            self,
            store=Depends(get_role_store),
            key_normalizer=Depends(ULN),
            role_validators=Depends(get_role_validators)
    ):
        super().__init__(
            store,
            key_normalizer=key_normalizer,
            role_validators=role_validators
        )


def get_user_claim_principal_factory(
        user_manager=Depends(UserManager),
        role_manager=Depends(RoleManager),
):
    return UCPF(user_manager, role_manager, opt)


cookie_handler = CookieAuthenticationHandler(secret_key='cookie')

provider = AuthenticationSchemeProvider()
provider.schemes[IdentityConstants.ApplicationScheme] = AuthenticationScheme(
    IdentityConstants.ApplicationScheme, cookie_handler
)
provider.schemes[IdentityConstants.TwoFactorUserIdScheme] = AuthenticationScheme(
    IdentityConstants.TwoFactorUserIdScheme, cookie_handler
)
provider.schemes[IdentityConstants.TwoFactorRememberMeScheme] = AuthenticationScheme(
    IdentityConstants.TwoFactorRememberMeScheme, cookie_handler
)

HttpContext.schemes = provider


class SignInManager(SIM):
    def __init__(
            self,
            user_manager=Depends(UserManager),
            context=Depends(HttpContext),
            claims_factory=Depends(get_user_claim_principal_factory),
            confirmation=Depends(get_user_confirmation)
    ):
        super().__init__(
            user_manager=user_manager,
            context=context,
            confirmation=confirmation,
            claims_factory=claims_factory,
            schemes=provider
        )


class EmailService:
    def send(self, _to: str, _title: str, msg: str):
        pass
