from pydentity.contrib.fastapi.authorization.abc import IAuthorizationProvider
from pydentity.contrib.fastapi.authorization.options import AuthorizationOptions
from pydentity.contrib.fastapi.authorization.policy import AuthorizationPolicy
from pydentity.exc import ArgumentNoneException


class AuthorizationProvider(IAuthorizationProvider):
    options: AuthorizationOptions

    def get_policy(self, name: str) -> AuthorizationPolicy | None:
        if not name:
            raise ArgumentNoneException('name')

        return getattr(self.options, '_scheme_map').get(name, None)
