from collections.abc import Callable
from datetime import timedelta
from typing import overload

from pydentity import IdentityConstants
from pydentity.authentication import (
    AuthenticationOptions,
    AuthenticationScheme,
    AuthenticationSchemeBuilder,
)
from pydentity.authentication.abc import IAuthenticationDataProtector
from pydentity.ext.fastapi.authentication.bearer import (
    JWTBearerAuthenticationHandler,
    TokenValidationParameters,
)
from pydentity.ext.fastapi.authentication.cookie import (
    CookieAuthenticationOptions,
    CookieAuthenticationHandler,
)


class AuthenticationBuilder:
    __slots__ = ("_options", "_dependencies")

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
            options: CookieAuthenticationOptions | None = None
    ) -> "AuthenticationBuilder":
        return self.add_scheme(
            scheme,
            AuthenticationScheme(scheme, CookieAuthenticationHandler(options))
        )

    def add_cookie_data_protector(self, protector: IAuthenticationDataProtector) -> "AuthenticationBuilder":
        for scheme in getattr(self._options, "_scheme_map").values():
            if issubclass(type(scheme.handler), CookieAuthenticationHandler):
                scheme.handler.protector = protector
        return self

    def add_identity_cookies(self) -> "AuthenticationBuilder":
        self.add_cookie(IdentityConstants.ApplicationScheme)
        self.add_cookie(IdentityConstants.ExternalScheme, CookieAuthenticationOptions(timespan=timedelta(minutes=10)))
        self.add_cookie(IdentityConstants.TwoFactorRememberMeScheme)
        self.add_cookie(IdentityConstants.TwoFactorUserIdScheme)
        return self

    def add_jwt_bearer(
            self,
            scheme: str = "Bearer",
            *,
            validation_parameters: TokenValidationParameters
    ) -> "AuthenticationBuilder":
        self.add_scheme(
            scheme,
            AuthenticationScheme(scheme, JWTBearerAuthenticationHandler(validation_parameters))
        )
        return self
