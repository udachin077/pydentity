import logging
from typing import Generic, Optional, Iterable

from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.exc import ArgumentNoneException
from pydentity.identity_result import IdentityResult
from pydentity.lookup_normalizer import ILookupNormalizer
from pydentity.role_validator import IRoleValidator
from pydentity.abc.stores import IRoleStore
from pydentity.types import TRole


class RoleManager(Generic[TRole]):
    """Provides the APIs for managing roles in a persistence store."""

    def __init__(
            self,
            store: IRoleStore[TRole],
            *,
            role_validators: Optional[Iterable[IRoleValidator[TRole]]] = None,
            key_normalizer: Optional[ILookupNormalizer] = None,
            errors: IdentityErrorDescriber = None,
            logger: Optional[logging.Logger] = None
    ):
        """
        Constructs a new instance of RoleManager[TRole].

        :param store: The persistence store the manager will operate over.
        :param role_validators: A collection of validators for roles.
        :param key_normalizer: The normalizer to use when normalizing role names to keys.
        :param errors: The IdentityErrorDescriber used to provider error messages.
        :param logger: The logger used to log messages, warnings and errors.

        ## Example

        from pydentity import RoleValidator, UpperLookupNormalizer

        manager = RoleManager(
            RoleStore(),
            role_validators=[RoleValidator()],
            key_normalizer=[UpperLookupNormalizer()]
        )
        """
        if store is None:
            raise ArgumentNoneException("store")

        self.store = store
        self.role_validators = role_validators
        self.key_normalizer = key_normalizer
        self.error_describer: IdentityErrorDescriber = errors or IdentityErrorDescriber()
        self.logger: logging.Logger = logger or logging.getLogger(self.__class__.__name__)

    async def all(self) -> list[TRole]:
        """
        Get all roles.

        :return:
        """
        return await self.store.all()

    async def create(self, role: TRole) -> IdentityResult:
        """
        Create the specified role.

        :param role: The role to create.
        :return:
        """
        if role is None:
            raise ArgumentNoneException("role")

        result = await self._validate_role(role)

        if not result.succeeded:
            return result

        await self.update_normalized_role_name(role)
        return await self.store.create(role)

    async def update(self, role: TRole) -> IdentityResult:
        """
        Updates the specified role.

        :param role: The role to update.
        :return:
        """
        if role is None:
            raise ArgumentNoneException("role")

        return await self._update_role(role)

    async def delete(self, role: TRole) -> IdentityResult:
        """
        Deletes the specified role.

        :param role: The role to delete.
        :return:
        """
        if role is None:
            raise ArgumentNoneException("role")

        return await self.store.delete(role)

    async def role_exists(self, role_name: str) -> bool:
        """
        Gets a flag indicating whether the specified role_name exists.

        :param role_name: The role name whose existence should be checked.
        :return:
        """
        if role_name is None:
            raise ArgumentNoneException("role_name")

        return await self.find_by_name(role_name) is not None

    async def get_role_id(self, role: TRole) -> str:
        """
        Gets the ID of the specified role.

        :param role: The role whose ID should be retrieved
        :return:
        """
        if role is None:
            raise ArgumentNoneException("role")

        return await self.store.get_role_id(role)

    async def find_by_id(self, role_id: str) -> Optional[TRole]:
        """
        Finds the role associated with the specified role_id if any.

        :param role_id: The role ID whose role should be returned.
        :return:
        """
        if role_id is None:
            raise ArgumentNoneException("role_id")

        return await self.store.find_by_id(role_id)

    async def get_role_name(self, role: TRole) -> Optional[str]:
        """
        Gets the name of the specified role.

        :param role: The role whose name should be retrieved.
        :return:
        """
        if role is None:
            raise ArgumentNoneException("role")

        return await self.store.get_role_name(role)

    async def set_role_name(self, role: TRole, name: Optional[str] = None):
        """
        Sets the name of the specified role.

        :param role: The role whose name should be set.
        :param name: The name to set.
        :return:
        """
        if role is None:
            raise ArgumentNoneException("role")

        await self.store.set_role_name(role, name)
        await self.update_normalized_role_name(role)
        return IdentityResult.success()

    async def find_by_name(self, role_name: str) -> Optional[TRole]:
        """
         Finds the role associated with the specified role_name if any.

        :param role_name: The name of the role to be returned.
        :return:
        """
        if role_name is None:
            raise ArgumentNoneException("role_name")

        return await self.store.find_by_name(self._normalize_key(role_name))

    async def update_normalized_role_name(self, role: TRole) -> None:
        """
        Updates the normalized name for the specified role.

        :param role: The role whose normalized name needs to be updated.
        :return:
        """
        if role is None:
            raise ArgumentNoneException("role")

        name = await self.store.get_role_name(role)
        await self.store.set_normalized_role_name(role, self._normalize_key(name))

    async def _validate_role(self, role: TRole) -> IdentityResult:
        """
        Should return IdentityResult.Success if validation is successful.
        This is called before saving the role via create or update.

        :param role:
        :return:
        """
        errors = []

        for rv in self.role_validators:
            result = await rv.validate(self, role)

            if not result.succeeded:
                errors.extend(result.errors)

        if errors:
            self.logger.warning("Role validation failed: %s." % ', '.join(e.code for e in errors))
            return IdentityResult.failed(*errors)

        return IdentityResult.success()

    def _normalize_key(self, key: Optional[str]) -> Optional[str]:
        """
        Gets a normalized representation of the specified key.

        :param key:
        :return:
        """
        return self.key_normalizer.normalize_name(key) if self.key_normalizer else key

    async def _update_role(self, role: TRole) -> IdentityResult:
        """
        Called to update the role after validating and updating the normalized role name.

        :param role:
        :return:
        """
        result = await self._validate_role(role)

        if not result.succeeded:
            return result

        await self.update_normalized_role_name(role)
        return await self.store.update(role)
