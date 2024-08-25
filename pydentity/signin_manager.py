import logging
from collections.abc import Iterable
from typing import Generic

from pydentity.abc import IUserClaimsPrincipalFactory, IUserConfirmation
from pydentity.authentication.abc import IAuthenticationSchemeProvider
from pydentity.user_confirmation import DefaultUserConfirmation
from pydentity.exc import ArgumentNoneException
from pydentity.http.context import HttpContext
from pydentity.identity_constants import IdentityConstants
from pydentity.identity_error import IdentityError
from pydentity.identity_options import IdentityOptions
from pydentity.identity_result import IdentityResult
from pydentity.security.claims import ClaimsPrincipal, Claim, ClaimTypes, ClaimsIdentity
from pydentity.types import TUser
from pydentity.user_manager import UserManager


class TwoFactorAuthenticationInfo:
    __slots__ = ('user', 'login_provider',)

    def __init__(self, user: TUser, login_provider: str):
        self.user = user
        self.login_provider = login_provider


class SignInResult:
    __slots__ = ('_succeeded', '_is_locked_out', '_is_not_allowed', '_requires_two_factor',)

    def __init__(
            self,
            succeeded: bool = False,
            is_locked_out: bool = False,
            is_not_allowed: bool = False,
            requires_two_factor: bool = False
    ):
        self._succeeded = succeeded
        self._is_locked_out = is_locked_out
        self._is_not_allowed = is_not_allowed
        self._requires_two_factor = requires_two_factor

    @property
    def is_locked_out(self) -> bool:
        return self._is_locked_out

    @property
    def succeeded(self) -> bool:
        return self._succeeded

    @property
    def is_not_allowed(self) -> bool:
        return self._is_not_allowed

    @property
    def requires_two_factor(self) -> bool:
        return self._requires_two_factor

    @staticmethod
    def success() -> 'SignInResult':
        return SignInResult(succeeded=True)

    @staticmethod
    def locked_out() -> 'SignInResult':
        return SignInResult(is_locked_out=True)

    @staticmethod
    def not_allowed() -> 'SignInResult':
        return SignInResult(is_not_allowed=True)

    @staticmethod
    def two_factor_required() -> 'SignInResult':
        return SignInResult(requires_two_factor=True)

    @staticmethod
    def failed() -> 'SignInResult':
        return SignInResult()

    def __str__(self) -> str:
        if self._is_locked_out:
            return 'Locked out'
        if self.is_not_allowed:
            return 'Not Allowed'
        if self.requires_two_factor:
            return 'Requires Two-Factor'
        if self._succeeded:
            return 'Succeeded'
        return 'Failed'


class SignInManager(Generic[TUser]):
    """Provides the APIs for user sign in."""

    __slots__ = (
        'user_manager',
        'options',
        'claims_factory',
        'logger',
        'authentication_scheme',
        '_confirmation',
        '_schemes',
        '__two_factor_info',
        '__context',
    )

    def __init__(
            self,
            user_manager: UserManager[TUser],
            context: HttpContext,
            schemes: IAuthenticationSchemeProvider,
            claims_factory: IUserClaimsPrincipalFactory[TUser],
            confirmation: IUserConfirmation[TUser],
            options: IdentityOptions | None = None,
            logger: logging.Logger | None = None
    ):
        if not user_manager:
            raise ArgumentNoneException('user_manager')
        if not claims_factory:
            raise ArgumentNoneException('claims_factory')

        self.user_manager: UserManager = user_manager
        self.options: IdentityOptions = options or IdentityOptions()
        self.claims_factory: IUserClaimsPrincipalFactory[TUser] = claims_factory
        self.logger: logging.Logger = logger or logging.Logger(self.__class__.__name__)
        self.authentication_scheme = IdentityConstants.ApplicationScheme
        self._confirmation = confirmation or DefaultUserConfirmation()
        self._schemes = schemes
        self.__two_factor_info: TwoFactorAuthenticationInfo | None = None
        self.__context = context

    @property
    def context(self) -> HttpContext:
        return self.__context

    async def is_signed_in(self, principal: ClaimsPrincipal) -> bool:
        """
        Returns true if the principal has an identity with the application cookie identity.

        :param principal: The ``ClaimsPrincipal`` instance.
        :return:
        """
        if not principal:
            raise ArgumentNoneException('principal')

        return any([True for i in principal.identities if i.authentication_type == self.authentication_scheme])

    async def can_sign_in(self, user: TUser) -> bool:
        """
        Returns a flag indicating whether the specified user can sign in.

        :param user: The user whose sign-in status should be returned.
        :return:
        """
        if (
                self.options.signin.required_confirmed_email and
                not await self.user_manager.is_email_confirmed(user)
        ):
            self.logger.debug('User cannot sign in without a confirmed email.')
            return False

        if (
                self.options.signin.required_confirmed_phone_number and
                not await self.user_manager.is_phone_number_confirmed(user)
        ):
            self.logger.debug('User cannot sign in without a confirmed phone number.')
            return False

        if (
                self.options.signin.required_confirmed_account and
                not await self._confirmation.is_confirmed(self.user_manager, user)
        ):
            self.logger.debug('User cannot sign in without a confirmed account.')
            return False

        return True

    async def refresh_sign_in(self, user: TUser):
        """


        :param user: The user to sign-in.
        :return:
        """
        auth = await self.context.authenticate(self.authentication_scheme)

        claims = []
        if auth and auth.principal:
            authentication_method = auth.principal.find_first(ClaimTypes.AuthenticationMethod)
            amr = auth.principal.find_first('amr')
            if authentication_method:
                claims.append(authentication_method)
            if amr:
                claims.append(amr)

        await self.sign_in_with_claims(user, auth.properties['is_persistent'], claims)

    async def sign_in(self, user: TUser, is_persistent: bool, authentication_method: str | None = None):
        additional_claims = []
        if authentication_method:
            additional_claims.append(Claim(ClaimTypes.AuthenticationMethod, authentication_method))

        return await self.sign_in_with_claims(user, is_persistent, additional_claims)

    async def sign_in_with_claims(
            self,
            user: TUser,
            is_persistent: bool,
            additional_claims: Iterable[Claim]
    ):
        """
        Signs in the specified user.

        :param user:
        :param is_persistent:
        :param additional_claims:
        :return:
        """
        user_principal = await self.create_user_principal(user)
        user_principal.identity.add_claims(*additional_claims)
        await self.context.sign_in(
            self.authentication_scheme,
            user_principal,
            is_persistent=is_persistent
        )
        self.context.user = user_principal

    async def sign_out(self):
        """
        Signs the current user out of the application.

        :return:
        """
        await self.context.sign_out(self.authentication_scheme)

        if await self._schemes.get_scheme(IdentityConstants.ExternalScheme):
            await self.context.sign_out(IdentityConstants.ExternalScheme)

        if await self._schemes.get_scheme(IdentityConstants.TwoFactorUserIdScheme):
            await self.context.sign_out(IdentityConstants.TwoFactorUserIdScheme)

    async def validate_security_stamp(self, principal: ClaimsPrincipal | None) -> TUser | None:
        """
        Validates the security stamp for the specified principal against the persisted stamp for the current user.

        :param principal:
        :return:
        """
        user = await self.user_manager.get_user(principal)
        if await self.is_valid_security_stamp(
                user,
                principal.find_first_value(self.options.claims_identity.security_stamp_claim_type)
        ):
            return user

        self.logger.debug('Failed to validate a security stamp.')
        return None

    async def is_valid_security_stamp(self, user: TUser, security_stamp: str) -> bool:
        """
        Validates the security stamp for the specified user.
        If no user is specified, or if the stores does not support security stamps, validation is considered successful.

        :param user: The user whose stamp should be validated.
        :param security_stamp: The expected security stamp value.
        :return: The result of the validation.
        """
        return (
                user is not None and
                # Only validate the security stamp if the store supports it
                (
                        not self.user_manager.supports_user_security_stamp or
                        security_stamp == await self.user_manager.get_security_stamp(user)
                )
        )

    async def validate_two_factory_security_stamp(self, principal: ClaimsPrincipal | None) -> TUser | None:
        """
        Validates the security stamp for the specified principal from one of
        the two-factor principals (remember client or user id) against
        the persisted stamp for the current user.

        :param principal:
        :return:
        """
        if not principal or not principal.identity or not principal.identity.name:
            return None

        user = await self.user_manager.find_by_id(principal.identity.name)
        if await self.is_valid_security_stamp(
                user,
                principal.find_first_value(self.options.claims_identity.security_stamp_claim_type)
        ):
            return user

        self.logger.debug('Failed to validate a security stamp.')
        return None

    async def password_sign_in(
            self,
            username: str,
            password: str,
            is_persistent: bool = False,
            lockout_on_failure: bool = True
    ) -> SignInResult:
        """
        Attempts to sign in the specified username and password combination.

        :param username: The username to sign in.
        :param password: The password to attempt to sign in with.
        :param is_persistent: Flag indicating whether the sign-in cookie should persist after the browser is closed.
        :param lockout_on_failure: Flag indicating if the user account should be locked if the sign in fails.
        :return:
        """
        user = await self.user_manager.find_by_name(username)

        if not user:
            return SignInResult.failed()

        attempt = await self.check_password_sign_in(user, password, lockout_on_failure)

        if attempt.succeeded:
            return await self._sign_in_or_two_factor(user, is_persistent)

        return attempt

    async def check_password_sign_in(
            self,
            user: TUser,
            password: str,
            lockout_on_failure: bool
    ) -> SignInResult:
        """
        Attempts a password sign-in for a user.

        :param user: The user to sign in.
        :param password: The password to attempt to sign in with.
        :param lockout_on_failure: Flag indicating if the user account should be locked if the sign in fails.
        :return:
        """
        if not user:
            raise ArgumentNoneException('user')

        if error := await self._pre_sign_in_check(user):
            return error

        if await self.user_manager.check_password(user, password):
            if not await self._is_two_factor_enabled(user) or await self.is_two_factor_client_remembered(user):
                reset_lockout_result = await self._reset_lockout_with_result(user)
                if not reset_lockout_result.succeeded:
                    # `reset_lockout` got an unsuccessful result that could be caused by concurrency failures
                    # indicating an attacker could be trying to bypass the `max_failed_access_attempts` limit.
                    # Return the same failure we do when failing to increment the lockout to avoid giving an attacker
                    # extra guesses at the password.
                    return SignInResult.failed()

            return SignInResult.success()

        self.logger.warning('User failed to provide the correct password.')

        if self.user_manager.supports_user_lockout and lockout_on_failure:
            # If lockout is requested, increment access failed count which might lock out the user.
            increment_lockout_result = await self.user_manager.access_failed(user)

            if not increment_lockout_result.succeeded:
                # Return the same failure we do when resetting the lockout fails after a correct password.
                return SignInResult.failed()

            if await self.user_manager.is_locked_out(user):
                return await self._locked_out(user)

        return SignInResult.failed()

    async def is_two_factor_client_remembered(self, user: TUser) -> bool:
        """
        Returns a flag indicating if the current client browser has been remembered by two-factor authentication
        for the user attempting to login.

        :param user: The user attempting to login.
        :return:
        """
        if await self._schemes.get_scheme(IdentityConstants.TwoFactorRememberMeScheme) is None:
            return False

        user_id = await self.user_manager.get_user_id(user)
        result = await self.context.authenticate(IdentityConstants.TwoFactorRememberMeScheme)
        return result.principal and result.principal.find_first_value(ClaimTypes.Name) == user_id

    async def remember_two_factor_client(self, user: TUser):
        await self.context.sign_in(
            IdentityConstants.TwoFactorRememberMeScheme,
            await self._store_remember_client(user),
            is_persistent=True
        )

    async def forget_two_factor_client(self):
        return self.context.sign_out(IdentityConstants.TwoFactorRememberMeScheme)

    async def two_factor_recovery_code_sign_in(self, recovery_code: str) -> SignInResult:
        two_factor_info = await self.retrieve_two_factor_info()
        if not two_factor_info:
            return SignInResult.failed()

        result = await self.user_manager.redeem_two_factor_recovery_code(two_factor_info.user, recovery_code)
        if result.succeeded:
            return await self.__do_two_factor_sign_in(
                two_factor_info.user,
                two_factor_info,
                is_persistent=False,
                remember_client=False
            )

        return SignInResult.failed()

    async def __do_two_factor_sign_in(
            self,
            user: TUser,
            two_factor_info: TwoFactorAuthenticationInfo,
            is_persistent: bool,
            remember_client: bool
    ) -> SignInResult:
        reset_lockout_result = await self._reset_lockout_with_result(user)
        if not reset_lockout_result.succeeded:
            # ResetLockout got an unsuccessful result that could be caused by concurrency failures indicating an
            # attacker could be trying to bypass the `max_failed_access_attempts` limit. Return the same failure we do
            # when failing to increment the lockout to avoid giving an attacker extra guesses at the two-factor code.
            return SignInResult.failed()

        claims = [Claim('amr', 'mfa')]

        if two_factor_info.login_provider:
            claims.append(Claim(ClaimTypes.AuthenticationMethod, two_factor_info.login_provider))

        if await self._schemes.get_scheme(IdentityConstants.ExternalScheme):
            await self.context.sign_out(IdentityConstants.ExternalScheme)

        if await self._schemes.get_scheme(IdentityConstants.TwoFactorUserIdScheme):
            await self.context.sign_out(IdentityConstants.TwoFactorUserIdScheme)
            if remember_client:
                await self.remember_two_factor_client(user)

        await self.sign_in_with_claims(user, is_persistent, claims)
        return SignInResult.success()

    async def two_factor_authenticator_sign_in(
            self,
            code: str,
            is_persistent: bool,
            remember_client: bool
    ) -> SignInResult:
        """
        Validates the sign in code from an authenticator app and creates and signs in the user.

        :param code: The two-factor authentication code to validate.
        :param is_persistent: Flag indicating whether the sign-in cookie should persist after the browser is closed.
        :param remember_client: Flag indicating whether the current browser should be remembered, suppressing
                                all further two-factor authentication prompts.
        :return:
        """
        two_factor_info = await self.retrieve_two_factor_info()
        if not two_factor_info:
            return SignInResult.failed()

        user = two_factor_info.user
        error = await self._pre_sign_in_check(user)
        if error:
            return error

        if await self.user_manager.verify_two_factor_token(
                user,
                self.options.tokens.authenticator_token_provider,
                code
        ):
            return await self.__do_two_factor_sign_in(user, two_factor_info, is_persistent, remember_client)

        if self.user_manager.supports_user_lockout:
            increment_lockout_result = await self.user_manager.access_failed(user)
            if not increment_lockout_result.succeeded:
                return SignInResult.failed()

            if await self.user_manager.is_locked_out(user):
                return await self._locked_out(user)

        return SignInResult.failed()

    async def two_factor_sign_in(self, provider: str, code: str, is_persistent: bool, remember_client: bool):
        """
        Validates the two-factor sign in code and creates and signs in the user

        :param provider: The two-factor authentication provider to validate the code against.
        :param code: The two-factor authentication code to validate.
        :param is_persistent: Flag indicating whether the sign-in cookie should persist after the browser is closed.
        :param remember_client: Flag indicating whether the current browser should be remembered,
                                suppressing all further two-factor authentication prompts.
        :return:
        """
        two_factor_info = await self.retrieve_two_factor_info()
        if not two_factor_info:
            return SignInResult.failed()

        user = two_factor_info.user
        error = await self._pre_sign_in_check(user)
        if error:
            return error

        if await self.user_manager.verify_two_factor_token(user, provider, code):
            return await self.__do_two_factor_sign_in(user, two_factor_info, is_persistent, remember_client)

        if self.user_manager.supports_user_lockout:
            increment_lockout_result = await self.user_manager.access_failed(user)
            if not increment_lockout_result.succeeded:
                return SignInResult.failed()

            if await self.user_manager.is_locked_out(user):
                return await self._locked_out(user)

        return SignInResult.failed()

    async def get_two_factor_authentication_user(self):
        """
        Gets the TUser for the current two-factor authentication login.

        :return:
        """
        info = await self.retrieve_two_factor_info()
        return info.user if info else None

    def _store_two_factor_info(self, user_id: str, login_provider: str | None) -> ClaimsPrincipal:
        identity = ClaimsIdentity(authentication_type=IdentityConstants.TwoFactorUserIdScheme)
        identity.add_claims(Claim(ClaimTypes.Name, user_id))
        if login_provider:
            identity.add_claims(Claim(ClaimTypes.AuthenticationMethod, login_provider))
        return ClaimsPrincipal(identity)

    async def _store_remember_client(self, user: TUser) -> ClaimsPrincipal:
        user_id = await self.user_manager.get_user_id(user)
        remember_browser_identity = ClaimsIdentity(authentication_type=IdentityConstants.TwoFactorRememberMeScheme)
        remember_browser_identity.add_claims(Claim(ClaimTypes.Name, user_id))
        if self.user_manager.supports_user_security_stamp:
            stamp = await self.user_manager.get_security_stamp(user)
            remember_browser_identity.add_claims(Claim(self.options.claims_identity.security_stamp_claim_type, stamp))
        return ClaimsPrincipal(remember_browser_identity)

    async def _is_two_factor_enabled(self, user: TUser) -> bool:
        return (
                self.user_manager.supports_user_two_factor and
                await self.user_manager.get_two_factor_enabled(user) and
                len(await self.user_manager.get_valid_two_factor_providers(user)) > 0
        )

    async def _sign_in_or_two_factor(
            self,
            user: TUser,
            is_persistent: bool,
            login_provider: str | None = None,
            bypass_two_factor: bool = False
    ):
        if not bypass_two_factor and await self._is_two_factor_enabled(user):
            if not await self.is_two_factor_client_remembered(user):
                self.__two_factor_info = {
                    'user': user,
                    'login_provider': login_provider
                }
                if await self._schemes.get_scheme(IdentityConstants.TwoFactorUserIdScheme):
                    user_id = await self.user_manager.get_user_id(user)
                    await self.context.sign_in(
                        IdentityConstants.TwoFactorUserIdScheme,
                        self._store_two_factor_info(user_id, login_provider)
                    )
                return SignInResult.two_factor_required()

        if login_provider:
            await self.context.sign_out(IdentityConstants.ExternalScheme)

        if not login_provider:
            await self.sign_in_with_claims(
                user,
                is_persistent,
                [Claim('amr', 'pwd')]
            )
        else:
            await self.sign_in(user, is_persistent, login_provider)

        return SignInResult.success()

    async def retrieve_two_factor_info(self) -> TwoFactorAuthenticationInfo | None:
        if self.__two_factor_info:
            return self.__two_factor_info

        result = await self.context.authenticate(IdentityConstants.TwoFactorUserIdScheme)
        if not result or not result.principal:
            return None

        user_id = result.principal.find_first_value(ClaimTypes.Name)
        if not user_id:
            return None

        user = await self.user_manager.find_by_id(user_id)
        if not user:
            return None

        return TwoFactorAuthenticationInfo(user, result.principal.find_first_value(ClaimTypes.AuthenticationMethod))

    async def _is_locked_out(self, user: TUser) -> bool:
        """
        Used to determine if a user is considered locked out.

        :param user: The user.
        :return:
        """
        return self.user_manager.supports_user_lockout and await self.user_manager.is_locked_out(user)

    async def _locked_out(self, user: TUser) -> SignInResult:  # noqa
        """
        Returns a locked out SignInResult.

        :param user:
        :return:
        """
        self.logger.warning("User is currently locked out.")
        return SignInResult.locked_out()

    async def _pre_sign_in_check(self, user: TUser) -> SignInResult | None:
        """
        Used to ensure that a user is allowed to sign in.

        :param user:
        :return:
        """
        if not await self.can_sign_in(user):
            return SignInResult.not_allowed()

        if await self._is_locked_out(user):
            return await self._locked_out(user)

        return None

    async def create_user_principal(self, user: TUser) -> ClaimsPrincipal:
        return await self.claims_factory.create(user)

    async def _reset_lockout_with_result(self, user: TUser) -> IdentityResult:
        """
        Used to reset a user's lockout count.

        :param user: The user.
        :return:
        """
        if not self.user_manager.supports_user_lockout:
            return IdentityResult.success()

        result = await self.user_manager.reset_access_failed_count(user)

        if not result.succeeded:
            return IdentityResult.failed(
                IdentityError('ResetLockout', 'Reset lockout failed.'),
                *result.errors
            )

        return result
