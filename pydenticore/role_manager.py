import logging
from typing import Generic, Optional, Iterable, cast

from pydenticore.interfaces import IRoleValidator, ILookupNormalizer, ILogger
from pydenticore.interfaces.stores import IRoleStore, IRoleClaimStore
from pydenticore.exc import ArgumentNoneException, NotSupportedException
from pydenticore.identity_error_describer import IdentityErrorDescriber
from pydenticore.identity_result import IdentityResult
from pydenticore.loggers import role_manager_logger
from pydenticore.resources import Resources
from pydenticore.security.claims import Claim
from pydenticore.types import TRole

__all__ = ('RoleManager',)


class RoleManager(Generic[TRole]):
    """Provides the APIs for managing roles in a persistence store."""

    __slots__ = (
        'error_describer',
        'key_normalizer',
        'logger',
        'role_validators',
        'store',
    )

    def __init__(
            self,
            store: IRoleStore[TRole],
            *,
            role_validators: Optional[Iterable[IRoleValidator[TRole]]] = None,
            key_normalizer: Optional[ILookupNormalizer] = None,
            errors: Optional[IdentityErrorDescriber] = None,
            logger: Optional[ILogger["RoleManager"]] = None
    ) -> None:
        """
        Constructs a new instance of ``RoleManager[TRole]``.

        :param store: The persistence store the manager will operate over.
        :param role_validators: A collection of validators for roles.
        :param key_normalizer: The normalizer to use when normalizing role names to keys.
        :param errors: The ``IdentityErrorDescriber`` used to provider error messages.
        :param logger: The logger used to log messages, warnings and errors.
        """
        if store is None:
            raise ArgumentNoneException('store')

        self.store = store
        self.role_validators = role_validators
        self.key_normalizer = key_normalizer
        self.error_describer: IdentityErrorDescriber = errors or IdentityErrorDescriber()
        self.logger: logging.Logger = logger or role_manager_logger

    @property
    def supports_role_claims(self) -> bool:
        """
        Gets a flag indicating whether the underlying persistence store supports ``Claims`` for roles.

        :return:
        """
        return issubclass(type(self.store), IRoleClaimStore)

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
            raise ArgumentNoneException('role')

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
            raise ArgumentNoneException('role')

        return await self._update_role(role)

    async def delete(self, role: TRole) -> IdentityResult:
        """
        Deletes the specified role.

        :param role: The role to delete.
        :return:
        """
        if role is None:
            raise ArgumentNoneException('role')

        return await self.store.delete(role)

    async def role_exists(self, role_name: str) -> bool:
        """
        Gets a flag indicating whether the specified ``role_name`` exists.

        :param role_name: The role name whose existence should be checked.
        :return:
        """
        if role_name is None:
            raise ArgumentNoneException('role_name')

        return await self.find_by_name(role_name) is not None

    async def get_role_id(self, role: TRole) -> str:
        """
        Gets the ID of the specified role.

        :param role: The role whose ID should be retrieved
        :return:
        """
        if role is None:
            raise ArgumentNoneException('role')

        return await self.store.get_role_id(role)

    async def find_by_id(self, role_id: str) -> Optional[TRole]:
        """
        Finds the role associated with the specified ``role_id`` if any.

        :param role_id: The role ID whose role should be returned.
        :return:
        """
        if role_id is None:
            raise ArgumentNoneException('role_id')

        return await self.store.find_by_id(role_id)

    async def get_role_name(self, role: TRole) -> Optional[str]:
        """
        Gets the name of the specified role.

        :param role: The role whose name should be retrieved.
        :return:
        """
        if role is None:
            raise ArgumentNoneException('role')

        return await self.store.get_role_name(role)

    async def set_role_name(self, role: TRole, name: Optional[str] = None) -> IdentityResult:
        """
        Sets the name of the specified role.

        :param role: The role whose name should be set.
        :param name: The name to set.
        :return:
        """
        if role is None:
            raise ArgumentNoneException('role')

        await self.store.set_role_name(role, name)
        await self.update_normalized_role_name(role)
        return IdentityResult.success()

    async def find_by_name(self, role_name: str) -> Optional[TRole]:
        """
         Finds the role associated with the specified ``role_name`` if any.

        :param role_name: The name of the role to be returned.
        :return:
        """
        if not role_name:
            raise ArgumentNoneException('role_name')

        return await self.store.find_by_name(self._normalize_key(role_name))  # type: ignore

    async def update_normalized_role_name(self, role: TRole) -> None:
        """
        Updates the normalized name for the specified role.

        :param role: The role whose normalized name needs to be updated.
        :return:
        """
        if role is None:
            raise ArgumentNoneException('role')

        name = await self.store.get_role_name(role)
        await self.store.set_normalized_role_name(role, self._normalize_key(name))

    async def get_claims(self, role: TRole) -> list[Claim]:
        """
        Gets a list of claims associated with the specified role.

        :param role:
        :return:
        """
        if role is None:
            raise ArgumentNoneException('role')

        return await self._get_claim_store().get_claims(role)

    async def add_claim(self, role: TRole, claim: Claim) -> IdentityResult:
        """
        Adds a claim to a role.

        :param role:
        :param claim:
        :return:
        """
        if role is None:
            raise ArgumentNoneException('role')
        if claim is None:
            raise ArgumentNoneException('claim')

        store = self._get_claim_store()
        await store.add_claim(role, claim)
        return await self._update_role(role)

    async def remove_claim(self, role: TRole, claim: Claim) -> IdentityResult:
        """
        Removes a claim from a role.

        :param role:
        :param claim:
        :return:
        """
        if role is None:
            raise ArgumentNoneException('role')
        if claim is None:
            raise ArgumentNoneException('claim')

        await self._get_claim_store().remove_claim(role, claim)
        return await self._update_role(role)

    async def _validate_role(self, role: TRole) -> IdentityResult:
        """
        Should return IdentityResult.Success if validation is successful.
        This is called before saving the role via create or update.

        :param role:
        :return:
        """
        if self.role_validators:
            errors = []  # type: ignore
            for rv in self.role_validators:
                result = await rv.validate(self, role)
                if not result.succeeded:
                    errors.extend(result.errors)  # type: ignore

            if errors:
                self.logger.warning('Role validation failed: %s.' % ', '.join(e.code for e in errors))
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

    def _get_claim_store(self) -> IRoleClaimStore[TRole]:
        if self.supports_role_claims:
            return cast(IRoleClaimStore[TRole], self.store)
        raise NotSupportedException(Resources['StoreNotIRoleClaimStore'])