from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING

from pydentity.security.claims import ClaimsPrincipal

if TYPE_CHECKING:
    from pydentity.authentication import AuthenticationResult, AuthenticationScheme


class IAuthenticationHandler(ABC):
    @abstractmethod
    async def sign_in(self, context, scheme: str, principal: ClaimsPrincipal, **properties) -> None:
        pass

    @abstractmethod
    async def sign_out(self, context, scheme: str) -> None:
        pass

    @abstractmethod
    async def authenticate(self, context, scheme: str) -> 'AuthenticationResult':
        pass


class IAuthenticationSchemeProvider(ABC):
    @abstractmethod
    async def get_scheme(self, name: str) -> Optional['AuthenticationScheme']:
        pass

    @abstractmethod
    async def get_default_authentication_scheme(self) -> Optional['AuthenticationScheme']:
        pass

    @abstractmethod
    async def get_default_sign_in_scheme(self) -> Optional['AuthenticationScheme']:
        pass

    @abstractmethod
    async def get_default_sign_out_scheme(self) -> Optional['AuthenticationScheme']:
        pass

    @abstractmethod
    async def get_default_scheme(self) -> Optional['AuthenticationScheme']:
        pass
