from collections.abc import Iterable
from typing import Annotated

from fastapi import Depends, FastAPI
from starlette.responses import PlainTextResponse
from starlette.types import ExceptionHandler

from pydentity.authorization import (
    AuthorizationError,
    AuthorizationHandlerContext,
    AuthorizationPolicyProvider,
)
from pydentity.authorization.abc import IAuthorizationPolicyProvider
from pydentity.exc import InvalidOperationException
from pydentity.ext.fastapi.dependencies import FastAPIAuthorizationHandlerContext


def use_authorization(app: FastAPI, on_error: ExceptionHandler | None = None):
    if on_error:
        app.add_exception_handler(AuthorizationError, on_error)
    else:
        app.add_exception_handler(
            AuthorizationError,
            lambda req, exc: PlainTextResponse('Forbidden', status_code=403)
        )


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

    if policy:
        _policy = provider.get_policy(policy)

        if not _policy:
            raise InvalidOperationException(f"The AuthorizationPolicy named: '{policy}' was not found.")

        for req in _policy.requirements:
            await req.handle(context)

        if not context.has_succeeded:
            raise AuthorizationError()
