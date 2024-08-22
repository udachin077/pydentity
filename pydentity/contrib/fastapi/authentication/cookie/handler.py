import json
import sys
from functools import lru_cache

from pydentity.contrib.fastapi.authentication.abc import IAuthenticationHandler
from pydentity.contrib.fastapi.authentication.cookie.abc import ICookieAuthenticationSerializer
from pydentity.contrib.fastapi.authentication.cookie.options import CookieAuthenticationOptions
from pydentity.contrib.fastapi.authentication.result import AuthenticationResult
from pydentity.http.context import HttpContext
from pydentity.security.claims import ClaimsPrincipal
from pydentity.security.claims.serializer import ClaimsPrincipalSerializer
from pydentity.utils import datetime


@lru_cache
def get_cookie_name(scheme: str, name: str | None = None) -> str:
    return f'FastAPI.{name or scheme}'


class CookieAuthenticationHandler(IAuthenticationHandler):
    __slots__ = ('_options',)

    serializer: ICookieAuthenticationSerializer = None

    def __init__(self, options: CookieAuthenticationOptions):
        self._options = options

    async def authenticate(self, context: HttpContext, scheme: str) -> AuthenticationResult:
        return self._decode_cookies(scheme, context.request.cookies)

    async def sign_in(self, context: HttpContext, scheme: str, principal: ClaimsPrincipal, **properties):
        context.response.headers['Cache-Control'] = 'no-cache,no-store'
        context.response.headers['Pragma'] = 'no-cache'
        cookies = self._encode_cookies(scheme, principal, **properties)
        expires = None  # session

        if properties.get('is_persistent', False):
            expires = datetime.utcnow().add(self._options.timespan)

        for key, value in cookies.items():
            context.response.set_cookie(
                key=key,
                value=value,
                expires=expires,
                httponly=self._options.httponly,
                secure=self._options.secure,
                samesite=self._options.samesite
            )

    async def sign_out(self, context: HttpContext, scheme: str):
        for cookie in context.request.cookies:
            if cookie.startswith(get_cookie_name(scheme, self._options.name)):
                context.response.delete_cookie(key=cookie)

    def _encode_cookies(
            self,
            scheme: str,
            principal: ClaimsPrincipal,
            **properties
    ) -> dict[str, str]:
        encoded_principal = ClaimsPrincipalSerializer.serialize(principal)
        encoded_principal.update({'.properties': properties})
        cookie_name = get_cookie_name(scheme, self._options.name)
        enc_data = self.serializer.serialize(encoded_principal) if self.serializer else json.dumps(encoded_principal)

        if sys.getsizeof(enc_data) < 4090:
            return {cookie_name: enc_data}

        cookie_chunks, chunk_size = {}, 4090
        chunks = [enc_data[i:i + chunk_size] for i in range(0, len(enc_data), chunk_size)]
        cookie_chunks.update({cookie_name: f'chunks-{len(chunks)}'})
        cookie_chunks.update({f'{cookie_name}C{i + 1}': chunk for i, chunk in enumerate(chunks)})
        return cookie_chunks

    def _decode_cookies(
            self,
            scheme: str,
            cookies: dict[str, str]
    ) -> AuthenticationResult:
        cookie_name = get_cookie_name(scheme, self._options.name)

        if cookie_value := cookies.get(cookie_name, None):
            if cookie_value.startswith('chunks-'):
                chunks_count = int(cookie_value.removeprefix('chunks-'))
                cookie_value = ''.join(cookies[f'{cookie_name}C{i + 1}'] for i in range(chunks_count))

            dec_data = self.serializer.deserialize(cookie_value) if self.serializer else json.loads(cookie_value)
            properties = dec_data.pop('.properties')
            return AuthenticationResult(ClaimsPrincipalSerializer.deserialize(dec_data), properties)

        return AuthenticationResult(None, None)  # type: ignore
