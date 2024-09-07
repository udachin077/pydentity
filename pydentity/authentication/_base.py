import base64
import json
import platform
from collections.abc import Callable
from inspect import isfunction
from typing import overload, Optional, Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pydentity.authentication.abc import (
    IAuthenticationHandler,
    IAuthenticationSchemeProvider,
    IAuthenticationDataProtector
)
from pydentity.exc import ArgumentNoneException, InvalidOperationException
from pydentity.security.claims import ClaimsPrincipal

__all__ = (
    "AuthenticationError",
    "AuthenticationOptions",
    "AuthenticationResult",
    "AuthenticationScheme",
    "AuthenticationSchemeBuilder",
    "AuthenticationSchemeProvider",
    "DefaultAuthenticationDataProtector",
)


class AuthenticationError(Exception):
    pass


class AuthenticationResult:
    __slots__ = ("_principal", "_properties",)

    def __init__(self, principal: ClaimsPrincipal, properties: dict[str, Any]) -> None:
        self._principal = principal
        self._properties = properties

    @property
    def principal(self) -> ClaimsPrincipal:
        return self._principal

    @property
    def properties(self) -> dict[str, Any]:
        return self._properties

    def __bool__(self) -> bool:
        return bool(self._principal.identity and self._principal.identity.is_authenticated)


class AuthenticationScheme:
    __slots__ = ("name", "handler",)

    def __init__(self, name: str, handler: IAuthenticationHandler) -> None:
        if not name:
            raise ArgumentNoneException("name")
        if not handler:
            raise ArgumentNoneException("handler")

        self.name = name
        self.handler = handler


class AuthenticationSchemeBuilder:
    __slots__ = ("name", "handler",)

    def __init__(self, name: str, handler: IAuthenticationHandler | None = None) -> None:
        self.name = name
        self.handler = handler

    def build(self) -> AuthenticationScheme:
        if not self.handler:
            raise InvalidOperationException("'handler' must be configured to build an AuthenticationScheme.")
        return AuthenticationScheme(self.name, self.handler)


class AuthenticationOptions:
    __slots__ = (
        "_scheme_map",
        "default_scheme",
        "default_authentication_scheme",
        "default_sign_in_scheme",
        "default_sign_out_scheme",
        "required_authenticated_signin",
    )

    def __init__(self) -> None:
        self._scheme_map = {}
        self.default_scheme: str = ""
        self.default_authentication_scheme: str = ""
        self.default_sign_in_scheme: str = ""
        self.default_sign_out_scheme: str = ""
        self.required_authenticated_signin: bool = True

    @overload
    def add_scheme(self, name: str, scheme: AuthenticationScheme) -> None:
        pass

    @overload
    def add_scheme(self, name: str, configure_scheme: Callable[[AuthenticationSchemeBuilder], None]) -> None:
        pass

    def add_scheme(
            self,
            name: str,
            scheme_or_builder: AuthenticationScheme | Callable[[AuthenticationSchemeBuilder], None]
    ) -> None:
        if not name:
            raise ArgumentNoneException("name")
        if not scheme_or_builder:
            raise ArgumentNoneException("scheme_or_builder")

        if name in self._scheme_map:
            raise InvalidOperationException(f"Scheme already exists: {name}.")

        if isinstance(scheme_or_builder, AuthenticationScheme):
            self._scheme_map[name] = scheme_or_builder

        elif isfunction(scheme_or_builder):
            builder = AuthenticationSchemeBuilder(name)
            scheme_or_builder(builder)
            self._scheme_map[name] = builder.build()

        else:
            raise NotImplemented


class AuthenticationSchemeProvider(IAuthenticationSchemeProvider):
    options: AuthenticationOptions

    def __init__(self) -> None:
        self._auto_default_scheme = None
        for scheme in getattr(self.options, "_scheme_map").values():
            self._auto_default_scheme = scheme
            break

    async def get_scheme(self, name: str) -> Optional[AuthenticationScheme]:
        if not name:
            raise ArgumentNoneException("name")
        return getattr(self.options, "_scheme_map").get(name, None)

    async def get_default_authentication_scheme(self) -> Optional[AuthenticationScheme]:
        if name := self.options.default_authentication_scheme:
            return await self.get_scheme(name)
        return await self.get_default_scheme()

    async def get_default_sign_in_scheme(self) -> Optional[AuthenticationScheme]:
        if name := self.options.default_sign_in_scheme:
            return await self.get_scheme(name)
        return await self.get_default_scheme()

    async def get_default_sign_out_scheme(self) -> Optional[AuthenticationScheme]:
        if name := self.options.default_sign_out_scheme:
            return await self.get_scheme(name)
        return await self.get_default_sign_in_scheme()

    async def get_default_scheme(self) -> Optional[AuthenticationScheme]:
        if name := self.options.default_scheme:
            return await self.get_scheme(name)
        return self._auto_default_scheme


class DefaultAuthenticationDataProtector(IAuthenticationDataProtector):
    __slots__ = ("__fernet",)

    def __init__(self, key: bytes | str = None, salt: bytes | str = None):
        key = key or platform.node()
        salt = salt or self.__class__.__name__

        if isinstance(key, str):
            key = key.encode()

        if isinstance(salt, str):
            salt = salt.encode()

        kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 480000)
        key = base64.urlsafe_b64encode(kdf.derive(key))
        self.__fernet = Fernet(key)

    def protect(self, data: dict | None) -> str | None:
        if data:
            return str(self.__fernet.encrypt(json.dumps(data, separators=(",", ":")).encode()))
        return data

    def unprotect(self, data: str | None) -> dict | None:
        if data:
            return json.loads(self.__fernet.decrypt(data))
        return data
