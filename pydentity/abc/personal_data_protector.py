from abc import ABC, abstractmethod
from typing import Any, Optional


class IPersonalDataProtector(ABC):
    @staticmethod
    @abstractmethod
    def create_protector(purpose: str, salt: Optional[str] = None) -> "IPersonalDataProtector":
        pass

    @abstractmethod
    def protect(self, data: Any) -> Any:
        pass

    @abstractmethod
    def unprotect(self, data: Any) -> Any:
        pass
