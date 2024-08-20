from collections.abc import Callable
from inspect import isfunction
from typing import overload

from pydentity.contrib.fastapi.authorization.policy import AuthorizationPolicy, AuthorizationPolicyBuilder
from pydentity.exc import ArgumentNoneException, InvalidOperationException


class AuthorizationOptions:
    __slots__ = ('_policy_map', 'default_policy',)

    def __init__(self):
        self._policy_map: dict[str, AuthorizationPolicy] = {}
        self.default_policy = AuthorizationPolicyBuilder().require_authenticated_user().build()

    @overload
    def add_policy(self, name: str, policy: AuthorizationPolicy) -> None:
        pass

    @overload
    def add_policy(self, name: str, configure_policy: Callable[[AuthorizationPolicyBuilder], None]) -> None:
        pass

    def add_policy(
            self,
            name: str,
            _policy: AuthorizationPolicy | Callable[[AuthorizationPolicyBuilder], None]
    ) -> None:
        if not name:
            raise ArgumentNoneException('name')
        if not _policy:
            raise ArgumentNoneException('_policy')

        if name in self._policy_map:
            raise InvalidOperationException(f'Policy already exists: {name}.')

        if isinstance(_policy, AuthorizationPolicy):
            self._policy_map[name] = _policy
        elif isfunction(_policy):
            builder = AuthorizationPolicyBuilder()
            _policy(builder)
            self._policy_map[name] = builder.build()
        else:
            raise NotImplemented
