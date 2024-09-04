import json
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache
from typing import Literal

from pydentity.authentication import AuthenticationResult
from pydentity.authentication.abc import IAuthenticationHandler
from pydentity.http.context import HttpContext
from pydentity.security.claims import ClaimsPrincipal
from pydentity.security.claims.serializer import ClaimsPrincipalSerializer
from pydentity.utils import datetime


class ICookieAuthenticationSerializer(ABC):
    @abstractmethod
    def deserialize(self, data: str | None) -> dict | None:
        pass

    @abstractmethod
    def serialize(self, data: dict | None) -> str | None:
        pass


@lru_cache
def _get_cookie_name(scheme: str, name: str | None = None) -> str:
    return f"FastAPI.{name or scheme}"


class CookieAuthenticationOptions:
    __slots__ = (
        "domain",
        "httponly",
        "max_age",
        "name",
        "path",
        "samesite",
        "secure",
        "timespan",
    )

    def __init__(
            self,
            domain: str | None = None,
            httponly: bool = True,
            max_age: int | None = None,
            name: str | None = None,
            path: str = "/",
            samesite: Literal["lax", "strict", "none"] = "lax",
            secure: bool = True,
            timespan: timedelta | int | None = None,
    ):
        self.domain = domain
        self.httponly = httponly
        self.max_age = max_age
        self.name = name
        self.path = path
        self.samesite = samesite
        self.secure = secure
        self.timespan = timespan


class CookieAuthenticationHandler(IAuthenticationHandler):
    __slots__ = ("options",)

    serializer: ICookieAuthenticationSerializer = None

    def __init__(self, options: CookieAuthenticationOptions | None = None):
        self.options = options or CookieAuthenticationOptions()

    async def authenticate(self, context: HttpContext, scheme: str) -> AuthenticationResult:
        return self._decode_cookies(scheme, context.request.cookies)

    async def sign_in(self, context: HttpContext, scheme: str, principal: ClaimsPrincipal, **properties) -> None:
        context.response.headers["Cache-Control"] = "no-cache,no-store"
        context.response.headers["Pragma"] = "no-cache"
        cookies = self._encode_cookies(scheme, principal, **properties)
        expires = None

        if properties.get("is_persistent", False):
            expires = datetime.utcnow().add_days(7)
        elif self.options.timespan:
            expires = datetime.utcnow().add(self.options.timespan)

        for key, value in cookies.items():
            context.response.set_cookie(
                key=key,
                value=value,
                expires=expires,
                httponly=self.options.httponly,
                secure=self.options.secure,
                samesite=self.options.samesite,
                domain=self.options.domain
            )

    async def sign_out(self, context: HttpContext, scheme: str) -> None:
        for cookie in context.request.cookies:
            if cookie.startswith(_get_cookie_name(scheme, self.options.name)):
                context.response.delete_cookie(key=cookie)

    def _encode_cookies(
            self,
            scheme: str,
            principal: ClaimsPrincipal,
            **properties
    ) -> dict[str, str]:
        encoded_principal = ClaimsPrincipalSerializer.serialize(principal)
        encoded_principal.update({".properties": properties})
        cookie_name = _get_cookie_name(scheme, self.options.name)
        enc_data = self.serializer.serialize(encoded_principal) if self.serializer else json.dumps(encoded_principal)

        if sys.getsizeof(enc_data) < 4090:
            return {cookie_name: enc_data}

        cookie_chunks, chunk_size = {}, 4090
        chunks = [enc_data[i:i + chunk_size] for i in range(0, len(enc_data), chunk_size)]
        cookie_chunks.update({cookie_name: f"chunks-{len(chunks)}"})
        cookie_chunks.update({f"{cookie_name}C{i + 1}": chunk for i, chunk in enumerate(chunks)})
        return cookie_chunks

    def _decode_cookies(
            self,
            scheme: str,
            cookies: dict[str, str]
    ) -> AuthenticationResult:
        cookie_name = _get_cookie_name(scheme, self.options.name)

        if cookie_value := cookies.get(cookie_name, None):
            if cookie_value.startswith("chunks-"):
                chunks_count = int(cookie_value.removeprefix("chunks-"))
                cookie_value = "".join(cookies[f"{cookie_name}C{i + 1}"] for i in range(chunks_count))

            dec_data = self.serializer.deserialize(cookie_value) if self.serializer else json.loads(cookie_value)
            properties = dec_data.pop(".properties")
            principal = ClaimsPrincipalSerializer.deserialize(dec_data)
            return AuthenticationResult(principal, properties)

        return AuthenticationResult(ClaimsPrincipal(), {})
