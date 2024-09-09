from collections.abc import Callable, Iterable
from typing import overload, Annotated

from fastapi import Depends
from starlette.requests import Request

from pydentity.authorization import (
    AuthorizationError,
    AuthorizationHandlerContext,
    AuthorizationOptions,
    AuthorizationPolicy,
    AuthorizationPolicyBuilder,
    AuthorizationPolicyProvider,
)
from pydentity.authorization.abc import IAuthorizationPolicyProvider
from pydentity.exc import InvalidOperationException

__all__ = (
    "AuthorizationBuilder",
    "authorize",
)


class FastAPIAuthorizationHandlerContext(AuthorizationHandlerContext):
    def __init__(self, request: Request):
        super().__init__(request)


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


def authorize(roles: str | Iterable[str] | None = None, *, policy: str | None = None):
    async def wrapped(
            context: Annotated[AuthorizationHandlerContext, Depends(FastAPIAuthorizationHandlerContext)],
            provider: Annotated[IAuthorizationPolicyProvider, Depends(AuthorizationPolicyProvider)],
    ):
        if not (context and context.is_authenticated):
            raise AuthorizationError()

        await _check_roles(roles, context)
        await _check_policy(policy, context, provider)

    return Depends(wrapped)


async def _check_roles(roles: str | Iterable[str] | None, context: AuthorizationHandlerContext) -> None:
    if not context.user:
        raise AuthorizationError()

    if roles:
        if isinstance(roles, str):
            roles = set(roles.replace(" ", "").split(","))
        else:
            roles = set(roles)

        result = any([context.user.is_in_role(r) for r in roles])

        if not result:
            raise AuthorizationError()


async def _check_policy(
        policy: str | None,
        context: AuthorizationHandlerContext,
        provider: IAuthorizationPolicyProvider
) -> None:
    if default_policy := provider.get_default_policy():
        for req in default_policy.requirements:
            await req.handle(context)

    _policy = None

    if policy:
        _policy = provider.get_policy(policy)

    if not _policy:
        raise InvalidOperationException(f"The AuthorizationPolicy named: '{policy}' was not found.")

    for req in _policy.requirements:
        await req.handle(context)

    if not context.has_succeeded:
        raise AuthorizationError()
