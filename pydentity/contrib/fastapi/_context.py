from pydentity.abc.context import HttpContext as _HttpContext

from fastapi.requests import Request
from fastapi.responses import Response

from pydentity.security.claims import ClaimsPrincipal


class HttpContext(_HttpContext):
    def __init__(self, request: Request, response: Response):
        super().__init__(request, response)

    @property
    def user(self) -> ClaimsPrincipal:
        return self.request.user

    @user.setter
    def user(self, value: ClaimsPrincipal):
        self.request.scope["user"] = value
