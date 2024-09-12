from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from pydenticore.authorization._base import AuthorizationPolicy, AuthorizationHandlerContext


class IAuthorizationPolicyProvider(ABC):
    @abstractmethod
    def get_policy(self, name: str) -> Optional["AuthorizationPolicy"]:
        pass

    @abstractmethod
    def get_default_policy(self) -> Optional["AuthorizationPolicy"]:
        pass


class IAuthorizationHandler(ABC):
    @abstractmethod
    async def handle(self, context: "AuthorizationHandlerContext") -> None:
        pass
