from abc import abstractmethod

from fastapi.requests import Request

from pydentity.security.claims import ClaimsPrincipal


class AuthorizationHandlerContext:
    __slots__ = (
        '_request',
        '_fail_called',
        '_succeeded_called',
    )

    def __init__(self, request: Request) -> None:
        self._request = request
        self._fail_called = False
        self._succeeded_called = False

    @property
    def user(self) -> ClaimsPrincipal | None:
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
    async def handle(self, context: AuthorizationHandlerContext):
        pass
