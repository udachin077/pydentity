from collections.abc import Callable, Awaitable
from typing import Any, Literal

from pydentity.contrib.fastapi.authorization.handler import AuthorizationHandler
from pydentity.contrib.fastapi.authorization.handler import AuthorizationHandlerContext
from pydentity.exc import ArgumentNoneException


class AuthorizationPolicy:
    __slots__ = ('requirements',)

    def __init__(self, requirements: list[AuthorizationHandler]) -> None:
        self.requirements: list[AuthorizationHandler] = requirements or []


class RolesAuthorizationRequirement(AuthorizationHandler):
    __slots__ = ('allowed_roles', 'mode',)

    def __init__(self, *allowed_roles: str, mode: Literal['all', 'any'] = 'any'):
        if not allowed_roles:
            raise ArgumentNoneException('allowed_roles')
        self.allowed_roles = allowed_roles
        self.mode = mode

    async def handle(self, context: AuthorizationHandlerContext):
        if context.user:
            if context.user.is_in_roles(*self.allowed_roles, mode=self.mode):
                context.succeed()


class ClaimsAuthorizationRequirement(AuthorizationHandler):
    __slots__ = ('claim_type', 'allowed_values',)

    def __init__(self, claim_type: str, *allowed_values: Any):
        if not claim_type:
            raise ArgumentNoneException('claim_type')
        self.claim_type = claim_type
        self.allowed_values = allowed_values

    async def handle(self, context: AuthorizationHandlerContext):
        if context.user:
            predicate = lambda c: c.type == self.claim_type  # noqa
            if self.allowed_values:
                predicate = lambda c: c.type == self.claim_type and c.value in self.allowed_values  # noqa

            if any(True for c in context.user.claims if predicate(c)):
                context.succeed()


class NameAuthorizationRequirement(AuthorizationHandler):
    __slots__ = ('required_name',)

    def __init__(self, required_name: str):
        if not required_name:
            raise ArgumentNoneException('required_name')
        self.required_name = required_name

    async def handle(self, context: AuthorizationHandlerContext):
        if self.required_name == context.user.identity.name:
            context.succeed()


class AssertionRequirement(AuthorizationHandler):
    __slots__ = ('handler',)

    def __init__(self, handler: Callable[[AuthorizationHandlerContext], Awaitable[bool]]):
        if not handler:
            raise ArgumentNoneException('handler')
        self.handler = handler

    async def handle(self, context: AuthorizationHandlerContext):
        if await self.handler(context):
            context.succeed()


class DenyAnonymousAuthorizationRequirement(AuthorizationHandler):
    async def handle(self, context: AuthorizationHandlerContext):
        if context.is_authenticated:
            context.succeed()


class AuthorizationPolicyBuilder:

    def __init__(self):
        self._requirements: list[AuthorizationHandler] = []

    def add_requirements(self, *requirements: AuthorizationHandler) -> 'AuthorizationPolicyBuilder':
        if not requirements:
            raise ArgumentNoneException('requirements')
        self._requirements.extend(requirements)
        return self

    def require_claim(self, claim_type: str, *allowed_values: Any) -> 'AuthorizationPolicyBuilder':
        self._requirements.append(ClaimsAuthorizationRequirement(claim_type, *allowed_values))
        return self

    def require_role(self, *roles: str, mode: Literal['all', 'any'] = 'any') -> 'AuthorizationPolicyBuilder':
        self._requirements.append(RolesAuthorizationRequirement(*roles, mode=mode))
        return self

    def require_assertion(
            self,
            handler: Callable[[AuthorizationHandlerContext], Awaitable[bool]]
    ) -> 'AuthorizationPolicyBuilder':
        self._requirements.append(AssertionRequirement(handler))
        return self

    def require_authenticated_user(self) -> 'AuthorizationPolicyBuilder':
        self._requirements.append(DenyAnonymousAuthorizationRequirement())
        return self

    def build(self) -> AuthorizationPolicy:
        return AuthorizationPolicy(self._requirements)
