from typing import TYPE_CHECKING, Generic, override

from pydentity.abc import IUserTwoFactorTokenProvider
from pydentity.exc import ArgumentNoneException
from pydentity.rfc6238service import Rfc6238AuthenticationService
from pydentity.types import TUser
from pydentity.utils import is_none_or_empty

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = (
    'TotpSecurityStampBasedTokenProvider',
    'EmailTokenProvider',
    'PhoneNumberTokenProvider'
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

        :param manager: The :exc:`UserManager[TUser]` that can be used to retrieve user properties.
        :param purpose: The purpose the token will be used for.
        :param user: The user a token should be generated for.
        :return:
        """
        if manager is None:
            raise ArgumentNoneException('manager')

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

        :param manager: The :exc:`UserManager[TUser]` that can be used to retrieve user properties.
        :param purpose: The purpose the token will be used for.
        :param token: The token to validate.
        :param user: The user a token should be validated for.
        :return:
        """
        if manager is None:
            raise ArgumentNoneException('manager')

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

        :param manager: The :exc:`UserManager[TUser]` that can be used to retrieve user properties.
        :param purpose: The purpose the token will be generated for.
        :param user: The user a token should be generated for.
        :return:
        """
        if manager is None:
            raise ArgumentNoneException('manager')

        user_id = await manager.get_user_id(user)
        return f'Totp:{purpose}:{user_id}'.encode()


class EmailTokenProvider(TotpSecurityStampBasedTokenProvider[TUser], Generic[TUser]):
    """TokenProvider that generates tokens from the user's security stamp and notifies a user via email."""

    @override
    async def can_generate_two_factor(self, manager: 'UserManager[TUser]', user: TUser) -> bool:
        if manager is None:
            raise ArgumentNoneException('manager')

        email = await manager.get_email(user)
        return not is_none_or_empty(email) and await manager.is_email_confirmed(user)

    @override
    async def get_user_modifier(self, manager: 'UserManager[TUser]', purpose: str, user: TUser) -> bytes:
        if manager is None:
            raise ArgumentNoneException('manager')

        email = await manager.get_email(user)
        return f'Email:{purpose}:{email}'.encode()


class PhoneNumberTokenProvider(TotpSecurityStampBasedTokenProvider[TUser], Generic[TUser]):
    """Represents a token provider that generates tokens from a user's security stamp and
    sends them to the user via their phone number."""

    @override
    async def can_generate_two_factor(self, manager: 'UserManager[TUser]', user: TUser) -> bool:
        if manager is None:
            raise ArgumentNoneException('manager')

        phone_number = await manager.get_phone_number(user)
        return not is_none_or_empty(phone_number) and await manager.is_phone_number_confirmed(user)

    @override
    async def get_user_modifier(self, manager: 'UserManager[TUser]', purpose: str, user: TUser) -> bytes:
        if manager is None:
            raise ArgumentNoneException('manager')

        phone_number = await manager.get_phone_number(user)
        return f'PhoneNumber:{purpose}:{phone_number}'.encode()
