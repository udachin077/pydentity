from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from pydentity.authorization import AuthorizationPolicy


class IAuthorizationPolicyProvider(ABC):
    @abstractmethod
    def get_policy(self, name: str) -> Optional['AuthorizationPolicy']:
        pass

    @abstractmethod
    def get_default_policy(self) -> Optional['AuthorizationPolicy']:
        pass
