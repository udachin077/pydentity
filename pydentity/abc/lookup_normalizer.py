from abc import ABC, abstractmethod
from typing import Optional


class ILookupNormalizer(ABC):
    """Provides an abstraction for normalizing keys (emails/names) for lookup purposes."""

    @abstractmethod
    def normalize_email(self, email: Optional[str]) -> Optional[str]:
        """
        Returns a normalized representation of the specified email.

        :param email: The email to normalize.
        :return: A normalized representation of the specified email.
        """

    @abstractmethod
    def normalize_name(self, name: Optional[str]) -> Optional[str]:
        """
        Returns a normalized representation of the specified name.

        :param name: The key to normalize.
        :return: A normalized representation of the specified name.
        """
