from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING

from pydentity.http.context import HttpContext
from pydentity.security.claims import ClaimsPrincipal

if TYPE_CHECKING:
    from pydentity.authentication import AuthenticationResult, AuthenticationScheme


class IAuthenticationHandler(ABC):
    @abstractmethod
    async def authenticate(self, context: HttpContext, scheme: str) -> "AuthenticationResult":
        pass

    @abstractmethod
    async def sign_in(self, context: HttpContext, scheme: str, principal: ClaimsPrincipal, **properties) -> None:
        pass

    @abstractmethod
    async def sign_out(self, context: HttpContext, scheme: str) -> None:
        pass


class IAuthenticationSchemeProvider(ABC):
    @abstractmethod
    async def get_scheme(self, name: str) -> Optional["AuthenticationScheme"]:
        pass

    @abstractmethod
    async def get_default_authentication_scheme(self) -> Optional["AuthenticationScheme"]:
        pass

    @abstractmethod
    async def get_default_sign_in_scheme(self) -> Optional["AuthenticationScheme"]:
        pass

    @abstractmethod
    async def get_default_sign_out_scheme(self) -> Optional["AuthenticationScheme"]:
        pass

    @abstractmethod
    async def get_default_scheme(self) -> Optional["AuthenticationScheme"]:
        pass
