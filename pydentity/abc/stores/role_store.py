from abc import ABC, abstractmethod
from typing import Generic, Optional

from pydentity.identity_result import IdentityResult
from pydentity.types import TRole


class IRoleStore(Generic[TRole], ABC):
    """Provides an abstraction for a storage and management of roles."""

    @abstractmethod
    def create_model_from_dict(self, **kwargs):
        """

        :param kwargs:
        :return:
        """

    @abstractmethod
    async def all(self) -> list[TRole]:
        """
        Returns all roles.

        :return:
        """

    @abstractmethod
    async def create(self, role: TRole) -> IdentityResult:
        """
        Create a new role in a store.

        :param role: The role to create in the store.
        :return:
        """

    @abstractmethod
    async def update(self, role: TRole) -> IdentityResult:
        """
        Updates a role from the store.

        :param role: The role to update in the store.
        :return:
        """

    @abstractmethod
    async def delete(self, role: TRole) -> IdentityResult:
        """
         Deletes a role from the store.

        :param role: The role to delete from the store.
        :return:
        """

    @abstractmethod
    async def find_by_id(self, role_id: str) -> Optional[TRole]:
        """
        Finds the role who has the specified ID.

        :param role_id: The role ID to look for.
        :return:
        """

    @abstractmethod
    async def find_by_name(self, normalized_name: str) -> Optional[TRole]:
        """
        Finds the role who has the specified normalized name.

        :param normalized_name: The normalized role name to look for.
        :return:
        """

    @abstractmethod
    async def get_role_id(self, role: TRole) -> str:
        """
        Gets the ID for a role from the store.

        :param role: The role whose ID should be returned.
        :return:
        """

    @abstractmethod
    async def get_role_name(self, role: TRole) -> Optional[str]:
        """
        Gets the name of a role from the store.

        :param role: The role whose name should be returned.
        :return:
        """

    @abstractmethod
    async def set_role_name(self, role: TRole, role_name: Optional[str]) -> None:
        """
        Sets the name of a role in the store.

        :param role: The role whose name should be set.
        :param role_name: The name of the role.
        :return:
        """

    @abstractmethod
    async def get_normalized_role_name(self, role: TRole) -> Optional[str]:
        """
        Get a role's normalized name.

        :param role: The role whose normalized name should be retrieved.
        :return:
        """

    @abstractmethod
    async def set_normalized_role_name(self, role: TRole, normalized_name: Optional[str]) -> None:
        """
        Set a role's normalized name.

        :param role: The role whose normalized name.
        :param normalized_name: The normalized name to set.
        :return:
        """
