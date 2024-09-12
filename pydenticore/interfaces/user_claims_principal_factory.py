from abc import ABC, abstractmethod
from typing import Generic

from pydenticore.security.claims import ClaimsPrincipal
from pydenticore.types import TUser


class IUserClaimsPrincipalFactory(Generic[TUser], ABC):
    """Provides an abstraction for a factory to create a ClaimsIdentity from a user."""

    @abstractmethod
    async def create(self, user: TUser) -> ClaimsPrincipal:
        """
        Creates a ``ClaimsPrincipal`` from a user.

        :param user: The user to create a ``ClaimsPrincipal`` from.
        :return:
        """
