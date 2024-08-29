import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Generic, override

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from pydentity.abc import IUserTwoFactorTokenProvider
from pydentity.rfc6238service import Rfc6238AuthenticationService
from pydentity.types import TUser
from pydentity.utils import is_none_or_empty

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = (
    'TotpSecurityStampBasedTokenProvider',
    'DataProtectorTokenProvider',
    'EmailTokenProvider',
    'PhoneNumberTokenProvider',
    'AuthenticatorTokenProvider',
)


class TotpSecurityStampBasedTokenProvider(IUserTwoFactorTokenProvider[TUser], Generic[TUser]):

    async def can_generate_two_factor(self, manager: 'UserManager[TUser]', user: TUser) -> bool:
        return True

    async def generate(self, manager: 'UserManager[TUser]', purpose: str, user: TUser) -> str:
        """
        Generates a token for the specified user and purpose.

        The purpose parameter allows a token generator to be used for multiple types of token whilst
        insuring a token for one purpose cannot be used for another. For example if you specified a purpose of "Email"
        and validated it with the same purpose a token with the purpose of TOTP would not pass the check even if it was
        for the same user.

        :param manager: The ``UserManager[TUser]`` that can be used to retrieve user properties.
        :param purpose: The purpose the token will be used for.
        :param user: The user a token should be generated for.
        :return:
        """
        security_token = await manager.create_security_token(user)
        modifier = await self.get_user_modifier(manager, purpose, user)
        return Rfc6238AuthenticationService.generate_code(
            security_token,
            modifier,
            interval=manager.options.tokens.totp_interval
        )

    async def validate(self, manager: 'UserManager[TUser]', purpose: str, token: str, user: TUser) -> bool:
        """
        Returns a flag indicating whether the specified token is valid for the given user and purpose.

        :param manager: The ``UserManager[TUser]`` that can be used to retrieve user properties.
        :param purpose: The purpose the token will be used for.
        :param token: The token to validate.
        :param user: The user a token should be validated for.
        :return:
        """
        security_token = await manager.create_security_token(user)
        modifier = await self.get_user_modifier(manager, purpose, user)
        return bool(security_token and Rfc6238AuthenticationService.validate_code(
            security_token,
            token,
            modifier,
            interval=manager.options.tokens.totp_interval
        ))

    async def get_user_modifier(self, manager: 'UserManager[TUser]', purpose: str, user: TUser) -> bytes:
        """
        Returns a constant, provider and user unique modifier used for entropy in generated tokens
        from user information.

        :param manager: The ``UserManager[TUser]`` that can be used to retrieve user properties.
        :param purpose: The purpose the token will be generated for.
        :param user: The user a token should be generated for.
        :return:
        """
        user_id = await manager.get_user_id(user)
        return f'Totp:{purpose}:{user_id}'.encode()


class EmailTokenProvider(TotpSecurityStampBasedTokenProvider[TUser], Generic[TUser]):
    """TokenProvider that generates tokens from the user's security stamp and notifies a user via email."""

    @override
    async def can_generate_two_factor(self, manager: 'UserManager[TUser]', user: TUser) -> bool:
        email = await manager.get_email(user)
        return not is_none_or_empty(email) and await manager.is_email_confirmed(user)

    @override
    async def get_user_modifier(self, manager: 'UserManager[TUser]', purpose: str, user: TUser) -> bytes:
        email = await manager.get_email(user)
        return f'Email:{purpose}:{email}'.encode()


class PhoneNumberTokenProvider(TotpSecurityStampBasedTokenProvider[TUser], Generic[TUser]):
    """Represents a token provider that generates tokens from a user's security stamp and
    sends them to the user via their phone number."""

    @override
    async def can_generate_two_factor(self, manager: 'UserManager[TUser]', user: TUser) -> bool:
        phone_number = await manager.get_phone_number(user)
        return not is_none_or_empty(phone_number) and await manager.is_phone_number_confirmed(user)

    @override
    async def get_user_modifier(self, manager: 'UserManager[TUser]', purpose: str, user: TUser) -> bytes:
        phone_number = await manager.get_phone_number(user)
        return f'PhoneNumber:{purpose}:{phone_number}'.encode()


class AuthenticatorTokenProvider(IUserTwoFactorTokenProvider[TUser], Generic[TUser]):
    @override
    async def generate(self, manager: 'UserManager[TUser]', purpose: str, user: TUser) -> str:
        return ''

    @override
    async def validate(self, manager: 'UserManager[TUser]', purpose: str, token: str, user: TUser) -> bool:
        key = await manager.get_authenticator_key(user)
        if is_none_or_empty(key):
            return False
        return Rfc6238AuthenticationService.validate_code(key.encode(), token)

    @override
    async def can_generate_two_factor(self, manager: 'UserManager[TUser]', user: TUser) -> bool:
        key = await manager.get_authenticator_key(user)
        return not is_none_or_empty(key)


class DataProtectorTokenProvider(IUserTwoFactorTokenProvider[TUser], Generic[TUser]):
    def __init__(self, purpose: str | None = None, token_lifespan: timedelta = timedelta(minutes=10)):
        self._serializer = URLSafeTimedSerializer(purpose or 'DataProtectorTokenProvider')
        self._token_lifespan = int(token_lifespan.total_seconds())
        self.logger = logging.Logger(self.__class__.__name__)

    async def generate(self, manager: 'UserManager[TUser]', purpose: str, user: TUser) -> str:
        user_id = await manager.get_user_id(user)
        stamp = None
        if manager.supports_user_security_stamp:
            stamp = await manager.get_security_stamp(user)

        data = {'user_id': user_id, 'purpose': purpose or '', 'stamp': stamp or ''}
        return self._serializer.dumps(data)

    async def can_generate_two_factor(self, manager: 'UserManager[TUser]', user: TUser) -> bool:
        return False

    async def validate(self, manager: 'UserManager[TUser]', purpose: str, token: str, user: TUser) -> bool:
        try:
            data = self._serializer.loads(token, max_age=self._token_lifespan)
        except BadSignature:
            self.logger.error('Bad signature')
            return False
        except SignatureExpired:
            self.logger.error('Invalid expiration time')
            return False
        else:
            try:
                if data['user_id'] != await manager.get_user_id(user):
                    self.logger.error('User ID not equals')
                    return False

                if data['purpose'] != purpose:
                    self.logger.error('Purpose not equals')
                    return False

                if manager.supports_user_security_stamp:
                    is_equals_security_stamp = data['stamp'] != await manager.get_security_stamp(user)
                    if not is_equals_security_stamp:
                        self.logger.error('Security stamp not equals')
                    return is_equals_security_stamp

                stamp_is_empty = bool(data['stamp'])
                if not stamp_is_empty:
                    self.logger.error('Security stamp is not empty')
                return stamp_is_empty

            except KeyError as ex:
                self.logger.error(ex)
                return False
