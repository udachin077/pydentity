from abc import abstractmethod, ABC

from pydenticore.authentication import AuthenticationResult
from pydenticore.authentication.interfaces import IAuthenticationService, IAuthenticationSchemeProvider
from pydenticore.exc import InvalidOperationException
from pydenticore.security.claims import ClaimsPrincipal
from pydenticore.types import TRequest, TResponse


class HttpContext:
    __slots__ = ("_request", "_response", "_schemes",)

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
        """Gets the Request object for this request."""
        return self._request

    @property
    def response(self) -> TResponse:
        """Gets the Response object for this request."""
        return self._response

    @property
    def user(self) -> ClaimsPrincipal | None:
        """Gets the user for this request."""
        return self._getuser()

    @user.setter
    def user(self, value: ClaimsPrincipal | None) -> None:
        """Sets the user for this request."""
        self._setuser(value)

    @abstractmethod
    def _getuser(self) -> ClaimsPrincipal | None:
        pass

    @abstractmethod
    def _setuser(self, value: ClaimsPrincipal | None) -> None:
        pass

    async def authenticate(self, scheme: str) -> AuthenticationResult:
        return await (await self.get_authentication_service(scheme)).authenticate(self, scheme)

    async def sign_in(self, scheme: str, principal: ClaimsPrincipal, **properties) -> None:
        await (await self.get_authentication_service(scheme)).sign_in(self, scheme, principal, **properties)

    async def sign_out(self, scheme: str) -> None:
        await (await self.get_authentication_service(scheme)).sign_out(self, scheme)

    async def get_authentication_service(self, name: str) -> IAuthenticationService:
        if scheme := await self._schemes.get_scheme(name):
            return scheme.handler
        raise InvalidOperationException(f"Scheme {name} not registered.")


class IHttpContextAccessor(ABC):
    def __init__(self, context: HttpContext):
        self.__http_context = context

    @property
    def http_context(self) -> HttpContext:
        """Gets or sets the current ``HttpContext``. Returns None if there is no active ``HttpContext``."""
        return self.__http_context
