from abc import ABC, abstractmethod
from typing import Generic

from pydentity.security.claims import ClaimsIdentity
from pydentity.types import TUser


class IUserClaimsPrincipalFactory(Generic[TUser], ABC):
    """Provides an abstraction for a factory to create a ClaimsIdentity from a user."""

    @abstractmethod
    async def create(self, user: TUser) -> ClaimsIdentity:
        """
        Creates a ClaimsIdentity from an user.

        :param user: The user to create a :exc:`ClaimsIdentity` from.
        :return:
        """
