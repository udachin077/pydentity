from collections.abc import Callable
from typing import overload

from pydentity.authorization import AuthorizationOptions, AuthorizationPolicy, AuthorizationPolicyBuilder


class AuthorizationBuilder:
    __slots__ = ("_options",)

    def __init__(self, options: AuthorizationOptions):
        self._options = options

    @overload
    def add_policy(self, name: str, policy: AuthorizationPolicy) -> "AuthorizationBuilder":
        pass

    @overload
    def add_policy(
            self,
            name: str,
            configure_policy: Callable[[AuthorizationPolicyBuilder], None]
    ) -> "AuthorizationBuilder":
        pass

    def add_policy(
            self,
            name: str,
            policy_or_builder: AuthorizationPolicy | Callable[[AuthorizationPolicyBuilder], None]
    ) -> "AuthorizationBuilder":
        self._options.add_policy(name, policy_or_builder)
        return self
