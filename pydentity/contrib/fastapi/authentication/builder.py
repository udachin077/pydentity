from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import overload, Literal

from pydentity.contrib.fastapi.authentication.options import AuthenticationOptions
from pydentity.contrib.fastapi.authentication.scheme import AuthenticationScheme, AuthenticationSchemeBuilder
from pydentity.identity_constants import IdentityConstants


@dataclass
class CookieAuthenticationOptions:
    name: str | None = None
    max_age: int | None = None
    expire_time_span: timedelta = timedelta(days=14)
    path: str = "/"
    domain: str | None = None
    secure: bool = True
    httponly: bool = True
    samesite: Literal["lax", "strict", "none"] = "lax"


class AuthenticationBuilder:
    __slots__ = ('_options',)

    def __init__(self, options: AuthenticationOptions):
        self._options = options

    @overload
    def add_scheme(self, name: str, policy: AuthenticationScheme) -> 'AuthenticationBuilder':
        pass

    @overload
    def add_scheme(
            self,
            name: str,
            configure_policy: Callable[[AuthenticationSchemeBuilder], None]
    ) -> 'AuthenticationBuilder':
        pass

    def add_scheme(
            self,
            name: str,
            soc: AuthenticationScheme | Callable[[AuthenticationSchemeBuilder], None]
    ) -> 'AuthenticationBuilder':
        self._options.add_scheme(name, soc)
        return self

    def add_cookie(self, scheme: str, configure: Callable[[CookieAuthenticationOptions], None]):
        options = CookieAuthenticationOptions()
        configure(options)

        def configure_scheme(b: AuthenticationSchemeBuilder):
            b.name = scheme
            b.handler = CookieAuthenticationHandler()

        return self.add_scheme(scheme, )

    def add_identity_cookies(self):
        self.add_application_cookie()
        self.add_external_cookie()
        self.add_two_factor_remember_me_cookie()
        self.add_two_factor_user_id_cookie()

    def add_application_cookie(self):
        def configure(o: CookieAuthenticationOptions):
            pass

        self.add_cookie(IdentityConstants.ApplicationScheme, configure)

    def add_external_cookie(self):
        def configure(o: CookieAuthenticationOptions):
            o.name = IdentityConstants.ExternalScheme
            o.expire_time_span = timedelta(minutes=5)

        self.add_cookie(IdentityConstants.ExternalScheme, configure)

    def add_two_factor_remember_me_cookie(self):
        def configure(o: CookieAuthenticationOptions):
            o.name = IdentityConstants.TwoFactorRememberMeScheme

        self.add_cookie(IdentityConstants.TwoFactorRememberMeScheme, configure)

    def add_two_factor_user_id_cookie(self):
        def configure(o: CookieAuthenticationOptions):
            o.name = IdentityConstants.TwoFactorUserIdScheme

        self.add_cookie(IdentityConstants.TwoFactorUserIdScheme, configure)
