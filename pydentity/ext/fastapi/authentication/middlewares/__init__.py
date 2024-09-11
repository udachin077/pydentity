from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp, Scope, Receive, Send

from pydentity.authentication import AuthenticationError
from pydentity.authentication.abc import IAuthenticationSchemeProvider
from pydentity.ext.fastapi.dependencies import HttpContext


class AuthenticationMiddleware(BaseHTTPMiddleware):
    __slots__ = ("app", "schemes",)

    def __init__(self, app: ASGIApp, schemes: IAuthenticationSchemeProvider) -> None:
        super().__init__(app)
        self.app = app
        self.schemes = schemes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ["http", "websocket"]:
            await self.app(scope, receive, send)
            return

        scope["user"] = None
        scope["auth"] = False

        context = HttpContext(Request(scope), None, self.schemes)

        try:
            default_authenticate = await self.schemes.get_default_authentication_scheme()

            if default_authenticate:
                result = await context.authenticate(default_authenticate.name)

                if result.principal and result.principal.identities:
                    scope["user"] = result.principal
                    scope["auth"] = result.principal.identity.is_authenticated

        except AuthenticationError as exc:
            pass

        await self.app(scope, receive, send)
