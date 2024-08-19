from abc import abstractmethod, ABC
from typing import TypeVar

from pydentity.authentication.abc import IAuthenticationHandler, IAuthenticationSchemeProvider
from pydentity.authentication.result import AuthenticationResult
from pydentity.exc import InvalidOperationException
from pydentity.security.claims import ClaimsPrincipal

TRequest = TypeVar('TRequest')
TResponse = TypeVar('TResponse')


class HttpContext(ABC):
    schemes: IAuthenticationSchemeProvider

    def __init__(self, request: TRequest, response: TResponse):
        self.__request = request
        self.__response = response

    @property
    def request(self) -> TRequest:
        return self.__request

    @property
    def response(self) -> TResponse:
        return self.__response

    @property
    @abstractmethod
    def user(self) -> ClaimsPrincipal:
        pass

    @user.setter
    @abstractmethod
    def user(self, value: ClaimsPrincipal):
        pass

    async def authenticate(self, scheme: str) -> AuthenticationResult:
        return await (await self.get_authentication_service(scheme)).authenticate(self, scheme)

    async def sign_in(self, scheme: str, principal: ClaimsPrincipal, **properties) -> None:
        await (await self.get_authentication_service(scheme)).sign_in(self, scheme, principal, **properties)

    async def sign_out(self, scheme: str) -> None:
        await (await self.get_authentication_service(scheme)).sign_out(self, scheme)

    async def get_authentication_service(self, name: str) -> IAuthenticationHandler:
        if scheme := await self.schemes.get_scheme(name):
            return scheme.handler
        raise InvalidOperationException('scheme not registered')
