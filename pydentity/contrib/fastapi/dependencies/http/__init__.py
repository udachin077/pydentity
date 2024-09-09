from typing import Annotated

from fastapi import Depends
from fastapi.requests import Request
from fastapi.responses import Response

from pydentity.authentication import AuthenticationSchemeProvider
from pydentity.authentication.abc import IAuthenticationSchemeProvider
from pydentity.http.context import IHttpContextAccessor, HttpContext as _HttpContext
from pydentity.security.claims import ClaimsPrincipal


class HttpContext(_HttpContext):
    def __init__(
            self,
            request: Request,
            response: Response,
            schemes: Annotated[IAuthenticationSchemeProvider, Depends(AuthenticationSchemeProvider)]
    ):
        super().__init__(request, response, schemes)

    def _getuser(self) -> ClaimsPrincipal | None:
        return self.request.user

    def _setuser(self, value: ClaimsPrincipal | None) -> None:
        self.request.scope["user"] = value


class HttpContextAccessor(IHttpContextAccessor):
    def __init__(self, context: Annotated[HttpContext, Depends()]):
        super().__init__(context)
