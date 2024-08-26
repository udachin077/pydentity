from abc import abstractmethod
from collections.abc import Callable, Awaitable, Iterable
from inspect import isfunction
from typing import Optional, Literal, Any, overload

from pydentity.authorization.abc import IAuthorizationPolicyProvider
from pydentity.exc import ArgumentNoneException, InvalidOperationException
from pydentity.security.claims import ClaimsPrincipal

__all__ = (
    'AuthorizationError',
    'AuthorizationOptions',
    'AuthorizationPolicy',
    'AuthorizationPolicyBuilder',
    'AuthorizationHandlerContext',
    'AuthorizationHandler',
    'AuthorizationPolicyProvider',
)


class AuthorizationError(Exception):
    pass


class AuthorizationHandlerContext[TRequest]:
    __slots__ = (
        '_request',
        '_fail_called',
        '_succeeded_called',
    )

    def __init__(self, request: TRequest) -> None:
        self._request = request
        self._fail_called = False
        self._succeeded_called = False

    @property
    def user(self) -> Optional[ClaimsPrincipal]:
        return self._request.user

    @property
    def is_authenticated(self) -> bool:
        return self._request.auth

    @property
    def has_succeeded(self) -> bool:
        return not self._fail_called and self._succeeded_called

    def fail(self) -> None:
        self._fail_called = True

    def succeed(self) -> None:
        self._succeeded_called = True


class AuthorizationHandler:
    @abstractmethod
    async def handle(self, context: AuthorizationHandlerContext) -> None:
        pass


class AuthorizationPolicy:
    __slots__ = ('requirements',)

    def __init__(self, requirements: Iterable[AuthorizationHandler]) -> None:
        requirements = requirements or []
        self.requirements: list[AuthorizationHandler] = list(requirements)


class RolesAuthorizationRequirement(AuthorizationHandler):
    __slots__ = ('allowed_roles', 'mode',)

    def __init__(self, *allowed_roles: str, mode: Literal['all', 'any'] = 'any') -> None:
        if not allowed_roles:
            raise ArgumentNoneException('allowed_roles')

        self.allowed_roles = allowed_roles
        self.mode = mode

    async def handle(self, context: 'AuthorizationHandlerContext') -> None:
        if context.user:
            if context.user.is_in_roles(*self.allowed_roles, mode=self.mode):
                context.succeed()


class ClaimsAuthorizationRequirement(AuthorizationHandler):
    __slots__ = ('claim_type', 'allowed_values',)

    def __init__(self, claim_type: str, *allowed_values: Any) -> None:
        if not claim_type:
            raise ArgumentNoneException('claim_type')

        self.claim_type = claim_type
        self.allowed_values = allowed_values

    async def handle(self, context: AuthorizationHandlerContext) -> None:
        if context.user:
            predicate = lambda c: c.type == self.claim_type  # noqa
            if self.allowed_values:
                predicate = lambda c: c.type == self.claim_type and c.value in self.allowed_values  # noqa

            if any(True for c in context.user.claims if predicate(c)):
                context.succeed()


class NameAuthorizationRequirement(AuthorizationHandler):
    __slots__ = ('required_name',)

    def __init__(self, required_name: str) -> None:
        if not required_name:
            raise ArgumentNoneException('required_name')

        self.required_name = required_name

    async def handle(self, context: AuthorizationHandlerContext) -> None:
        if context.user and context.user.identity and self.required_name == context.user.identity.name:
            context.succeed()


class AssertionRequirement(AuthorizationHandler):
    __slots__ = ('handler',)

    def __init__(self, handler: Callable[[AuthorizationHandlerContext], Awaitable[bool]]) -> None:
        if not handler:
            raise ArgumentNoneException('handler')

        self.handler = handler

    async def handle(self, context: AuthorizationHandlerContext) -> None:
        if await self.handler(context):
            context.succeed()


class DenyAnonymousAuthorizationRequirement(AuthorizationHandler):
    async def handle(self, context: AuthorizationHandlerContext) -> None:
        if context.is_authenticated:
            context.succeed()


class AuthorizationPolicyBuilder:
    __slots__ = ('_requirements',)

    def __init__(self) -> None:
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
            policy_or_builder: AuthorizationPolicy | Callable[[AuthorizationPolicyBuilder], None]
    ) -> None:
        if not name:
            raise ArgumentNoneException('name')
        if not policy_or_builder:
            raise ArgumentNoneException('policy_or_builder')
        if name in self._policy_map:
            raise InvalidOperationException(f'Policy already exists: {name}.')

        if isinstance(policy_or_builder, AuthorizationPolicy):
            self._policy_map[name] = policy_or_builder

        elif isfunction(policy_or_builder):
            builder = AuthorizationPolicyBuilder()
            policy_or_builder(builder)
            self._policy_map[name] = builder.build()

        else:
            raise NotImplemented


class AuthorizationPolicyProvider(IAuthorizationPolicyProvider):
    options: AuthorizationOptions

    def get_policy(self, name: str) -> Optional[AuthorizationPolicy]:
        if not name:
            raise ArgumentNoneException('name')
        return getattr(self.options, '_policy_map').get(name, None)

    def get_default_policy(self) -> Optional[AuthorizationPolicy]:
        return self.options.default_policy
