import sys
from collections.abc import Iterable
from functools import lru_cache
from itsdangerous.url_safe import URLSafeSerializer

from pydentity.http.context import HttpContext
from pydentity.contrib.fastapi.authentication.abc import IAuthenticationHandler
from pydentity.contrib.fastapi.authentication.result import AuthenticationResult
from pydentity.security.claims import ClaimsPrincipal
from pydentity.security.claims.serializer import ClaimsPrincipalSerializer
from pydentity.utils import datetime


class CookieAuthenticationHandler(IAuthenticationHandler):
    def __init__(
            self,
            secret_key: str | bytes | Iterable[str] | Iterable[bytes] | None = None,
            serializer: URLSafeSerializer | None = None,
            cookie_prefix: str = 'FastAPI.',
    ):
        if not secret_key and not serializer:
            raise ValueError('"secret_key" and "serializer" cannot be None')
        self._cookie_prefix = cookie_prefix
        self._serializer: URLSafeSerializer = serializer or URLSafeSerializer(secret_key)

    async def sign_in(self, context: HttpContext, scheme: str, principal: ClaimsPrincipal, **properties):
        context.response.headers['Cache-Control'] = 'no-cache,no-store'
        context.response.headers['Pragma'] = 'no-cache'
        cookies = self.__encode_principal_properties(scheme, principal, **properties)
        expires = datetime.utcnow().add_days(7) if properties.get('is_persistent', False) else None

        for key, value in cookies.items():
            context.response.set_cookie(
                key=key,
                value=value,
                expires=expires,
                # httponly=True,
                secure=True,
            )

    async def sign_out(self, context: HttpContext, scheme: str):
        for cookie in context.request.cookies:
            if cookie.startswith(self.get_cookie_name(scheme)):
                context.response.delete_cookie(key=cookie)

    async def authenticate(self, context: HttpContext, scheme: str) -> AuthenticationResult:
        principal, properties = self.__decode_principal_properties(scheme, context.request.cookies)
        return AuthenticationResult(principal, properties)

    def __encode_principal_properties(
            self,
            scheme: str,
            principal: ClaimsPrincipal,
            **properties
    ) -> dict[str, str]:
        encoded_principal = ClaimsPrincipalSerializer.serialize(principal)
        encoded_principal.update({'.properties': properties})
        encoded_data = self._serializer.dumps(encoded_principal)

        if sys.getsizeof(encoded_data) >= 4096:
            cookie_chunks, chunk_size = {}, 4090
            chunks = [encoded_data[i:i + chunk_size] for i in range(0, len(encoded_data), chunk_size)]
            cookie_chunks.update({self.get_cookie_name(scheme): f'chunks-{len(chunks)}'})

            for i, value in enumerate(chunks):
                cookie_chunks.update({f'{self.get_cookie_name(scheme)}C{i + 1}': value})
            return cookie_chunks

        return {self.get_cookie_name(scheme): encoded_data}

    def __decode_principal_properties(
            self,
            scheme: str,
            cookies: dict[str, str]
    ) -> tuple[ClaimsPrincipal, dict] | tuple[None, None]:
        if cookie_value := cookies.get(self.get_cookie_name(scheme), None):
            if cookie_value.startswith('chunks-'):
                chunks_count, chunks = int(cookie_value.removeprefix('chunks-')), []

                for i in range(chunks_count):
                    chunk_cookie = cookies[f'{self.get_cookie_name(scheme)}C{i + 1}']
                    chunks.append(chunk_cookie)

                cookie_value = ''.join(chunks)

            decoded_principal = self._serializer.loads(cookie_value)
            properties = decoded_principal.pop('.properties')
            return ClaimsPrincipalSerializer.deserialize(decoded_principal), properties

        return None, None

    @lru_cache
    def get_cookie_name(self, scheme: str) -> str:
        return self._cookie_prefix + scheme
