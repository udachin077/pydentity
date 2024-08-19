from abc import abstractmethod, ABC
from typing import TYPE_CHECKING, Optional

from pydentity.security.claims import ClaimsPrincipal

if TYPE_CHECKING:
    from pydentity.authentication.scheme import AuthenticationScheme
    from pydentity.authentication.result import AuthenticationResult

__all__ = ('IAuthenticationHandler', 'IAuthenticationSchemeProvider',)


class IAuthenticationHandler(ABC):
    @abstractmethod
    async def sign_in(self, context, scheme: str, principal: ClaimsPrincipal, **properties):
        pass

    @abstractmethod
    async def sign_out(self, context, scheme: str):
        pass

    @abstractmethod
    async def authenticate(self, context, scheme: str) -> 'AuthenticationResult':
        pass


class IAuthenticationSchemeProvider(ABC):
    @abstractmethod
    async def get_scheme(self, name: str) -> Optional['AuthenticationScheme']:
        pass
