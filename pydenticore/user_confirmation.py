from typing import Generic, TYPE_CHECKING

from pydenticore.interfaces import IUserConfirmation
from pydenticore.types import TUser

if TYPE_CHECKING:
    from pydenticore.user_manager import UserManager

__all__ = ('DefaultUserConfirmation',)


class DefaultUserConfirmation(IUserConfirmation[TUser], Generic[TUser]):
    """Default implementation of ``IUserConfirmation[TUser]``."""

    async def is_confirmed(self, manager: 'UserManager[TUser]', user: TUser) -> bool:
        return await manager.is_email_confirmed(user)
