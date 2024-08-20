from typing import Annotated

from fastapi import Depends

from pydentity import SignInManager
from pydentity.contrib.fastapi.authorization.abc import IAuthorizationProvider
from pydentity.contrib.fastapi.authorization.exc import AuthorizationError
from pydentity.contrib.fastapi.authorization.handler import AuthorizationHandlerContext
from pydentity.contrib.fastapi.authorization.provider import AuthorizationProvider
from pydentity.exc import InvalidOperationException


async def _check_roles(roles: set[str] | str, _context: AuthorizationHandlerContext) -> bool:
    if isinstance(roles, str):
        roles = set(roles.replace(' ', '').strip(',').split(','))

    return any([_context.user.is_in_role(r) for r in roles])


async def _check_policy(policy: str, _context: AuthorizationHandlerContext, _provider: IAuthorizationProvider) -> bool:
    _policy = _provider.get_policy(policy)

    if not _policy:
        raise InvalidOperationException(f'The AuthorizationPolicy named: "{policy}" was not found.')

    for req in _policy.requirements:
        await req.handle(_context)

    return _context.has_succeeded


def authorize(*, roles: set[str] | str | None = None, policy: str | None = None):
    """
    Specifies that the class or method to requires the specified authorization.

    :param roles: A comma delimited list of roles that are allowed to access the resource.
    :param policy: Policy name that determines access to the resource.
    :raise AuthorizationError:
    :return:

    """

    async def wrapped(
            _context: Annotated[AuthorizationHandlerContext, Depends()],
            _provider: Annotated[IAuthorizationProvider, Depends(AuthorizationProvider)],
            _manager: Annotated[SignInManager, Depends()]
    ):
        if not (_context and _context.is_authenticated and _context.user):
            raise AuthorizationError()

        if not await _manager.validate_security_stamp(_context.user):
            raise AuthorizationError()

        if roles:
            if not await _check_roles(roles, _context):
                raise AuthorizationError()

        if policy:
            if not await _check_policy(policy, _context, _provider):
                raise AuthorizationError()

    return wrapped
