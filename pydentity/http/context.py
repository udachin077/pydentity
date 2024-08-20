from typing import Annotated

from fastapi import Depends
from fastapi.requests import Request
from fastapi.responses import Response

from pydentity.contrib.fastapi.authentication.abc import IAuthenticationHandler, IAuthenticationSchemeProvider
from pydentity.contrib.fastapi.authentication.provider import AuthenticationSchemeProvider
from pydentity.contrib.fastapi.authentication.result import AuthenticationResult
from pydentity.exc import InvalidOperationException
from pydentity.security.claims import ClaimsPrincipal


class HttpContext:
    __slots__ = ('__request', '__response', '__schemes',)

    def __init__(
            self,
            request: Request,
            response: Response,
            schemes: Annotated[IAuthenticationSchemeProvider, Depends(AuthenticationSchemeProvider)]
    ):
        self.__request = request
        self.__response = response
        self.__schemes = schemes

    @property
    def request(self) -> Request:
        return self.__request

    @property
    def response(self) -> Response:
        return self.__response

    @property
    def user(self) -> ClaimsPrincipal | None:
        return self.request.user

    @user.setter
    def user(self, value: ClaimsPrincipal | None):
        self.request.scope['user'] = value

    async def authenticate(self, scheme: str) -> AuthenticationResult:
        return await (await self.get_authentication_service(scheme)).authenticate(self, scheme)

    async def sign_in(self, scheme: str, principal: ClaimsPrincipal, **properties) -> None:
        await (await self.get_authentication_service(scheme)).sign_in(self, scheme, principal, **properties)

    async def sign_out(self, scheme: str) -> None:
        await (await self.get_authentication_service(scheme)).sign_out(self, scheme)

    async def get_authentication_service(self, name: str) -> IAuthenticationHandler:
        if scheme := await self.__schemes.get_scheme(name):
            return scheme.handler
        raise InvalidOperationException(f'Scheme {name} not registered.')
