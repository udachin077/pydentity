from collections.abc import Callable
from datetime import timedelta
from typing import overload

from pydentity import IdentityConstants
from pydentity.authentication import AuthenticationOptions, AuthenticationScheme, AuthenticationSchemeBuilder
from pydentity.authentication.abc import IAuthenticationDataProtector
from pydentity.authentication.bearer import TokenValidationParameters, JWTBearerAuthenticationHandler
from pydentity.authentication.cookie import (
    CookieAuthenticationOptions,
    CookieAuthenticationHandler,
    DefaultCookieAuthenticationProtector,
)


class AuthenticationBuilder:
    __slots__ = ("_options", "_default_cookie_authentication_options",)

    def __init__(self, options: AuthenticationOptions) -> None:
        self._options = options

    @overload
    def add_scheme(self, name: str, scheme: AuthenticationScheme) -> "AuthenticationBuilder":
        pass

    @overload
    def add_scheme(
            self,
            name: str,
            configure_scheme: Callable[[AuthenticationSchemeBuilder], None]
    ) -> "AuthenticationBuilder":
        pass

    def add_scheme(
            self,
            name: str,
            scheme_or_builder: AuthenticationScheme | Callable[[AuthenticationSchemeBuilder], None]
    ) -> "AuthenticationBuilder":
        self._options.add_scheme(name, scheme_or_builder)
        return self

    def add_cookie(
            self,
            scheme: str = "Cookie",
            options: CookieAuthenticationOptions = None,
    ) -> "AuthenticationBuilder":
        return self.add_scheme(
            scheme,
            AuthenticationScheme(scheme, CookieAuthenticationHandler(options))
        )

    def add_cookie_protector(self, protector: IAuthenticationDataProtector) -> "AuthenticationBuilder":
        CookieAuthenticationHandler.protector = protector
        return self

    def add_identity_cookies(self, protector: IAuthenticationDataProtector = None) -> "AuthenticationBuilder":
        self._add_application_cookie()
        self._add_external_cookie()
        self._add_two_factor_remember_me_cookie()
        self._add_two_factor_user_id_cookie()

        if protector:
            self.add_cookie_protector(protector)
        else:
            self._add_default_cookie_protector()

        return self

    def _add_application_cookie(self) -> None:
        self.add_cookie(IdentityConstants.ApplicationScheme)

    def _add_external_cookie(self) -> None:
        options = CookieAuthenticationOptions(timespan=timedelta(minutes=5))
        self.add_cookie(IdentityConstants.ExternalScheme, options)

    def _add_two_factor_remember_me_cookie(self) -> None:
        self.add_cookie(IdentityConstants.TwoFactorRememberMeScheme)

    def _add_two_factor_user_id_cookie(self) -> None:
        self.add_cookie(IdentityConstants.TwoFactorUserIdScheme)

    def _add_default_cookie_protector(self) -> None:
        self.add_cookie_protector(DefaultCookieAuthenticationProtector())

    def add_jwt_bearer(
            self,
            scheme: str = "Bearer",
            validation_parameters: TokenValidationParameters | None = None
    ) -> "AuthenticationBuilder":
        self.add_scheme(
            scheme,
            AuthenticationScheme(scheme, JWTBearerAuthenticationHandler(validation_parameters))
        )
        return self
