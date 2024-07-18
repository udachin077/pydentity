from typing import Generic, TYPE_CHECKING

from pydentity.abc import IUserClaimsPrincipalFactory
from pydentity.exc import ArgumentNoneException
from pydentity.security.claims import ClaimsPrincipal, ClaimsIdentity, Claim, ClaimTypes
from pydentity.types import TUser, TRole

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager
    from pydentity.role_manager import RoleManager


class UserClaimsPrincipalFactory(IUserClaimsPrincipalFactory[TUser], Generic[TUser]):
    def __init__(
            self,
            user_manager: "UserManager[TUser]",
            role_manager: "RoleManager[TRole]"
    ):
        self.user_manager = user_manager
        self.role_manager = role_manager

    async def create(self, user: TUser) -> ClaimsPrincipal:
        if not user:
            raise ArgumentNoneException("user")

        user_id = await self.user_manager.get_user_id(user=user)
        username = await self.user_manager.get_username(user=user)

        identity = ClaimsIdentity()

        identity.add_claims(
            Claim(ClaimTypes.NameIdentifier, user_id),
            Claim(ClaimTypes.Name, username)
        )

        if self.user_manager.supports_user_email:
            if email := await self.user_manager.get_email(user):
                identity.add_claims(Claim(ClaimTypes.Email, email))

        if self.user_manager.supports_user_security_stamp:
            if security := await self.user_manager.get_security_stamp(user):
                identity.add_claims(Claim(ClaimTypes.SecurityStamp, security))

        if self.user_manager.supports_user_claim:
            if claims := await self.user_manager.get_claims(user):
                identity.add_claims(*claims)

        if self.user_manager.supports_user_role:
            roles = await self.user_manager.get_roles(user)
            for role_name in roles:
                identity.add_claims(Claim(ClaimTypes.Role, role_name))

        return ClaimsPrincipal(identity)
