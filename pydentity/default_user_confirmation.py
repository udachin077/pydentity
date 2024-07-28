from typing import Generic, TYPE_CHECKING

from pydentity.abc import IUserConfirmation
from pydentity.types import TUser

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager


class DefaultUserConfirmation(IUserConfirmation[TUser], Generic[TUser]):
    """Default implementation of :exc:`IUserConfirmation[TUser]`."""

    async def is_confirmed(self, manager: 'UserManager[TUser]', user: TUser) -> bool:
        return await manager.is_email_confirmed(user)
