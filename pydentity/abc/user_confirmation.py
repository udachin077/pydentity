from abc import ABC, abstractmethod
from typing import Generic, TYPE_CHECKING

from pydentity.types import TUser

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager


class IUserConfirmation(Generic[TUser], ABC):
    @abstractmethod
    async def is_confirmed(self, manager: "UserManager", user: TUser) -> bool:
        """

        :param manager:
        :param user:
        :return:
        """
