from collections.abc import Callable
from datetime import timedelta
from typing import overload

from pydentity.contrib.fastapi.authentication.cookie.abc import ICookieAuthenticationSerializer
from pydentity.contrib.fastapi.authentication.cookie.handler import CookieAuthenticationHandler
from pydentity.contrib.fastapi.authentication.cookie.options import CookieAuthenticationOptions
from pydentity.contrib.fastapi.authentication.cookie.default_cookie_serializer import (
    DefaultCookieAuthenticationSerializer
)
from pydentity.contrib.fastapi.authentication.options import AuthenticationOptions
from pydentity.contrib.fastapi.authentication.scheme import AuthenticationScheme, AuthenticationSchemeBuilder
from pydentity.identity_constants import IdentityConstants


class AuthenticationBuilder:
    __slots__ = ('_options',)

    def __init__(self, options: AuthenticationOptions) -> None:
        self._options = options

    @overload
    def add_scheme(self, name: str, scheme: AuthenticationScheme) -> 'AuthenticationBuilder':
        pass

    @overload
    def add_scheme(
            self,
            name: str,
            configure_scheme: Callable[[AuthenticationSchemeBuilder], None]
    ) -> 'AuthenticationBuilder':
        pass

    def add_scheme(
            self,
            name: str,
            scheme_or_builder: AuthenticationScheme | Callable[[AuthenticationSchemeBuilder], None]
    ) -> 'AuthenticationBuilder':
        self._options.add_scheme(name, scheme_or_builder)
        return self

    def add_cookie(
            self,
            scheme: str,
            options: CookieAuthenticationOptions = None,
    ) -> 'AuthenticationBuilder':
        return self.add_scheme(
            scheme,
            AuthenticationScheme(
                scheme,
                CookieAuthenticationHandler(options or CookieAuthenticationOptions())
            )
        )

    def add_cookie_serializer(
            self,
            serializer: ICookieAuthenticationSerializer
    ) -> 'AuthenticationBuilder':
        CookieAuthenticationHandler.serializer = serializer
        return self

    def add_identity_cookies(
            self,
            serializer: ICookieAuthenticationSerializer = None
    ) -> 'AuthenticationBuilder':
        self._add_application_cookie()
        self._add_external_cookie()
        self._add_two_factor_remember_me_cookie()
        self._add_two_factor_user_id_cookie()
        self.add_cookie_serializer(serializer) if serializer else self._add_default_cookie_serializer()
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

    def _add_default_cookie_serializer(self) -> None:  # noqa
        if CookieAuthenticationHandler.serializer is None:
            CookieAuthenticationHandler.serializer = DefaultCookieAuthenticationSerializer()
