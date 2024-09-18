from datetime import timedelta
from typing import TYPE_CHECKING, Generic, override

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from pydenticore.interfaces import IUserTwoFactorTokenProvider, ILogger
from pydenticore.loggers import data_protection_token_provider_logger
from pydenticore.token_providers.rfc6238service import generate_code, validate_code
from pydenticore.types import TUser
from pydenticore.utils import is_none_or_empty

if TYPE_CHECKING:
    from pydenticore.user_manager import UserManager

__all__ = (
    "AuthenticatorTokenProvider",
    "DataProtectorTokenProvider",
    "EmailTokenProvider",
    "PhoneNumberTokenProvider",
    "TotpSecurityStampBasedTokenProvider",
)


class TotpSecurityStampBasedTokenProvider(IUserTwoFactorTokenProvider[TUser], Generic[TUser]):

    async def can_generate_two_factor(self, manager: "UserManager[TUser]", user: TUser) -> bool:
        return True

    async def generate(self, manager: "UserManager[TUser]", purpose: str, user: TUser) -> str:
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
        return generate_code(
            security_token,
            modifier,
            interval=manager.options.tokens.totp_interval
        )

    async def validate(self, manager: "UserManager[TUser]", purpose: str, token: str, user: TUser) -> bool:
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
        return bool(security_token and validate_code(
            security_token,
            token,
            modifier,
            interval=manager.options.tokens.totp_interval
        ))

    async def get_user_modifier(self, manager: "UserManager[TUser]", purpose: str, user: TUser) -> bytes:
        """
        Returns a constant, provider and user unique modifier used for entropy in generated tokens
        from user information.

        :param manager: The ``UserManager[TUser]`` that can be used to retrieve user properties.
        :param purpose: The purpose the token will be generated for.
        :param user: The user a token should be generated for.
        :return:
        """
        user_id = await manager.get_user_id(user)
        return f"Totp:{purpose}:{user_id}".encode()


class EmailTokenProvider(TotpSecurityStampBasedTokenProvider[TUser], Generic[TUser]):
    """TokenProvider that generates tokens from the user"s security stamp and notifies a user via email."""

    @override
    async def can_generate_two_factor(self, manager: "UserManager[TUser]", user: TUser) -> bool:
        email = await manager.get_email(user)
        return not is_none_or_empty(email) and await manager.is_email_confirmed(user)

    @override
    async def get_user_modifier(self, manager: "UserManager[TUser]", purpose: str, user: TUser) -> bytes:
        email = await manager.get_email(user)
        return f"Email:{purpose}:{email}".encode()


class PhoneNumberTokenProvider(TotpSecurityStampBasedTokenProvider[TUser], Generic[TUser]):
    """Represents a token provider that generates tokens from a user"s security stamp and
    sends them to the user via their phone number."""

    @override
    async def can_generate_two_factor(self, manager: "UserManager[TUser]", user: TUser) -> bool:
        phone_number = await manager.get_phone_number(user)
        return not is_none_or_empty(phone_number) and await manager.is_phone_number_confirmed(user)

    @override
    async def get_user_modifier(self, manager: "UserManager[TUser]", purpose: str, user: TUser) -> bytes:
        phone_number = await manager.get_phone_number(user)
        return f"PhoneNumber:{purpose}:{phone_number}".encode()


class AuthenticatorTokenProvider(IUserTwoFactorTokenProvider[TUser], Generic[TUser]):
    @override
    async def generate(self, manager: "UserManager[TUser]", purpose: str, user: TUser) -> str:
        return ""

    @override
    async def validate(self, manager: "UserManager[TUser]", purpose: str, token: str, user: TUser) -> bool:
        key = await manager.get_authenticator_key(user)
        if is_none_or_empty(key):
            return False
        return validate_code(key.encode(), token)

    @override
    async def can_generate_two_factor(self, manager: "UserManager[TUser]", user: TUser) -> bool:
        key = await manager.get_authenticator_key(user)
        return not is_none_or_empty(key)


class DataProtectorTokenProvider(IUserTwoFactorTokenProvider[TUser], Generic[TUser]):
    __slots__ = ("_serializer", "_token_lifespan", "_logger",)

    def __init__(
            self,
            purpose: str | None = None,
            token_lifespan: int | timedelta = 600,
            logger: ILogger["DataProtectorTokenProvider"] | None = None
    ) -> None:
        """

        :param purpose:
        :param token_lifespan: The amount of time a generated token remains valid. Default to 600 seconds.
        :param logger:
        """
        self._serializer = URLSafeTimedSerializer(purpose or "DataProtectorTokenProvider")

        if isinstance(token_lifespan, timedelta):
            self._token_lifespan = int(token_lifespan.total_seconds())
        else:
            self._token_lifespan = token_lifespan

        self._logger = logger or data_protection_token_provider_logger

    async def generate(self, manager: "UserManager[TUser]", purpose: str, user: TUser) -> str:
        user_id = await manager.get_user_id(user)
        stamp = None
        if manager.supports_user_security_stamp:
            stamp = await manager.get_security_stamp(user)

        data = {"user_id": user_id, "purpose": purpose or "", "stamp": stamp or ""}
        return self._serializer.dumps(data)

    async def can_generate_two_factor(self, manager: "UserManager[TUser]", user: TUser) -> bool:
        return False

    async def validate(self, manager: "UserManager[TUser]", purpose: str, token: str, user: TUser) -> bool:
        try:
            data = self._serializer.loads(token, max_age=self._token_lifespan)
        except BadSignature:
            self._logger.error("Bad signature.")
            return False
        except SignatureExpired:
            self._logger.error("Invalid expiration time.")
            return False
        else:
            try:
                if data["user_id"] != await manager.get_user_id(user):
                    self._logger.error("User ID not equals.")
                    return False

                if data["purpose"] != purpose:
                    self._logger.error("Purpose not equals.")
                    return False

                if manager.supports_user_security_stamp:
                    is_equals_security_stamp = data["stamp"] == await manager.get_security_stamp(user)
                    if not is_equals_security_stamp:
                        self._logger.error("Security stamp not equals.")
                    return is_equals_security_stamp

                stamp_is_empty = not bool(data["stamp"])
                if not stamp_is_empty:
                    self._logger.error("Security stamp is not empty.")
                return stamp_is_empty

            except KeyError as ex:
                self._logger.error(str(ex))
                return False
