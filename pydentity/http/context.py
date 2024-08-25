from abc import abstractmethod

from pydentity.authentication import IAuthenticationSchemeProvider, AuthenticationResult, IAuthenticationHandler
from pydentity.exc import InvalidOperationException
from pydentity.security.claims import ClaimsPrincipal


class HttpContext[TRequest, TResponse]:
    __slots__ = ('_request', '_response', '_schemes',)

    def __init__(
            self,
            request: TRequest,
            response: TResponse,
            schemes: IAuthenticationSchemeProvider
    ) -> None:
        self._schemes = schemes
        self._request = request
        self._response = response

    @property
    def request(self) -> TRequest:
        return self._request

    @property
    def response(self) -> TResponse:
        return self._response

    @property
    def user(self) -> ClaimsPrincipal | None:
        return self.request.user

    @user.setter
    def user(self, value: ClaimsPrincipal | None) -> None:
        self.request.scope['user'] = value  # for FastAPI

    async def authenticate(self, scheme: str) -> AuthenticationResult:
        return await (await self.get_authentication_service(scheme)).authenticate(self, scheme)

    async def sign_in(self, scheme: str, principal: ClaimsPrincipal, **properties) -> None:
        await (await self.get_authentication_service(scheme)).sign_in(self, scheme, principal, **properties)

    async def sign_out(self, scheme: str) -> None:
        await (await self.get_authentication_service(scheme)).sign_out(self, scheme)

    async def get_authentication_service(self, name: str) -> IAuthenticationHandler:
        if scheme := await self._schemes.get_scheme(name):
            return scheme.handler
        raise InvalidOperationException(f'Scheme {name} not registered.')
