from typing import Generic, Optional, TYPE_CHECKING

from pydentity.abc import IRoleValidator
from pydentity.exc import ArgumentNoneException
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.types import TRole
from pydentity.utils import is_none_or_empty

if TYPE_CHECKING:
    from pydentity.role_manager import RoleManager

__all__ = ('RoleValidator',)


class RoleValidator(IRoleValidator[TRole], Generic[TRole]):
    """Provides the default validation of roles."""

    def __init__(self, errors: Optional[IdentityErrorDescriber] = None):
        """

        :param errors: The :exc:`IdentityErrorDescriber` used to provider error messages.
        """
        self._describer = errors or IdentityErrorDescriber()

    async def validate(self, manager: 'RoleManager[TRole]', role: TRole) -> IdentityResult:
        if manager is None:
            raise ArgumentNoneException('manager')
        if role is None:
            raise ArgumentNoneException('role')

        errors = []  # type: ignore

        await self._validate_role_name(manager, role, errors)

        if not errors:
            return IdentityResult.success()

        return IdentityResult.failed(*errors)

    async def _validate_role_name(self, manager: 'RoleManager[TRole]', role: TRole, errors):  # type: ignore
        role_name = await manager.get_role_name(role)
        if not is_none_or_empty(role_name):
            assert role_name is not None
            if owner := await manager.find_by_name(role_name):
                if await manager.get_role_id(owner) != await manager.get_role_id(role):
                    errors.append(self._describer.DuplicateRoleName(role_name))
        else:
            errors.append(self._describer.InvalidRoleName('None'))
