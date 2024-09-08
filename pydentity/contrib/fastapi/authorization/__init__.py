from collections.abc import Callable
from typing import overload

from fastapi import Depends

from pydentity import SignInManager
from pydentity.authorization import (
    AuthorizationError,
    AuthorizationHandlerContext,
    AuthorizationOptions,
    AuthorizationPolicy,
    AuthorizationPolicyBuilder,
    AuthorizationPolicyProvider,
)
from pydentity.exc import InvalidOperationException

__all__ = (
    "AuthorizationBuilder",
    "authorize",
)


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


def authorize(roles: set[str] | str | None = None, *, policy: str | None = None):
    """

    :param roles:
    :param policy:
    :return:
    """

    async def wrapped(
            context: AuthorizationHandlerContext = Depends(),
            provider: AuthorizationPolicyProvider = Depends(),
            manager: SignInManager = Depends()
    ):
        if not (context and context.is_authenticated):
            raise AuthorizationError()

        if not await manager.validate_security_stamp(context.user):
            raise AuthorizationError()

        if roles:
            await _check_roles(roles, context)

        if policy:
            await _check_policy(policy, context, provider)

    return wrapped


async def _check_roles(roles: set[str] | str, context: AuthorizationHandlerContext) -> None:
    if not context.user:
        raise AuthorizationError()

    if isinstance(roles, str):
        roles = set(roles.replace(" ", "").split(","))

    result = any([context.user.is_in_role(r) for r in roles])

    if not result:
        raise AuthorizationError()


async def _check_policy(
        policy: str,
        context: AuthorizationHandlerContext,
        provider: AuthorizationPolicyProvider
) -> None:
    _policy = provider.get_policy(policy)

    if not _policy:
        raise InvalidOperationException(f"The AuthorizationPolicy named: '{policy}' was not found.")

    for req in _policy.requirements:
        await req.handle(context)

    if not context.has_succeeded:
        raise AuthorizationError()
