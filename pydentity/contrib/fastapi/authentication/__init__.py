from collections.abc import Callable
from datetime import timedelta
from typing import overload

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp, Scope, Receive, Send

from pydentity import IdentityConstants
from pydentity.authentication import (
    AuthenticationError,
    AuthenticationOptions,
    AuthenticationScheme,
    AuthenticationSchemeBuilder,
)
from pydentity.authentication.abc import IAuthenticationDataProtector, IAuthenticationSchemeProvider
from pydentity.authentication.bearer import TokenValidationParameters, JWTBearerAuthenticationHandler
from pydentity.authentication.cookie import (
    CookieAuthenticationOptions,
    CookieAuthenticationHandler,
    DefaultCookieAuthenticationProtector,
)
from pydentity.contrib.fastapi.dependencies.http import HttpContext


class AuthenticationMiddleware(BaseHTTPMiddleware):
    __slots__ = ("app", "schemes", "on_error",)

    def __init__(self, app: ASGIApp, schemes: type[IAuthenticationSchemeProvider]) -> None:
        super().__init__(app)
        self.app = app
        self.schemes = schemes()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ["http", "websocket"]:
            await self.app(scope, receive, send)
            return

        scope["user"] = None
        scope["auth"] = False

        context = HttpContext(Request(scope), None, self.schemes)  # noqa

        try:
            default_authenticate = await self.schemes.get_default_authentication_scheme()

            if default_authenticate:
                result = await context.authenticate(default_authenticate.name)

                if result.principal and result.principal.identities:
                    scope["user"] = result.principal
                    scope["auth"] = result.principal.identity.is_authenticated

        except AuthenticationError as exc:
            pass

        await self.app(scope, receive, send)


class AuthenticationBuilder:
    __slots__ = ("_options",)

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
