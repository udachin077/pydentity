from abc import ABC, abstractmethod
from typing import Any


class IPersonalDataProtector(ABC):
    """Provides an abstraction used for personal data encryption."""

    @abstractmethod
    def protect(self, data: Any) -> str:
        """
        Protect the data.

        :param data: The data to protect.
        :return: The protected data.
        """

    @abstractmethod
    def unprotect(self, data: str) -> Any:
        """
        Unprotect the data.

        :param data: The data to unprotect.
        :return: The unprotected data.
        """
