from abc import ABC, abstractmethod

from pydentity.contrib.fastapi.authorization.policy import AuthorizationPolicy


class IAuthorizationProvider(ABC):
    @abstractmethod
    def get_policy(self, name: str) -> AuthorizationPolicy | None:
        pass
