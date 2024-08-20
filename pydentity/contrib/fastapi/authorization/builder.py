from collections.abc import Callable
from typing import overload

from pydentity.contrib.fastapi.authorization.options import AuthorizationOptions
from pydentity.contrib.fastapi.authorization.policy import AuthorizationPolicy, AuthorizationPolicyBuilder


class AuthorizationBuilder:

    def __init__(self, options: AuthorizationOptions):
        self._options = options

    @overload
    def add_policy(self, name: str, policy: AuthorizationPolicy) -> 'AuthorizationBuilder':
        pass

    @overload
    def add_policy(
            self,
            name: str,
            configure_policy: Callable[[AuthorizationPolicyBuilder], None]
    ) -> 'AuthorizationBuilder':
        pass

    def add_policy(
            self,
            name: str,
            poc: AuthorizationPolicy | Callable[[AuthorizationPolicyBuilder], None]
    ) -> 'AuthorizationBuilder':
        self._options.add_policy(name, poc)
        return self
