from pydentity.contrib.fastapi.authentication.abc import IAuthenticationHandler
from pydentity.exc import InvalidOperationException


class AuthenticationScheme:
    __slots__ = ('name', 'handler',)

    def __init__(self, name: str, handler: IAuthenticationHandler):
        self.name = name
        self.handler = handler


class AuthenticationSchemeBuilder:

    def __init__(self, name: str, handler: IAuthenticationHandler):
        self.name = name
        self.handler = handler

    def build(self):
        if not self.handler:
            raise InvalidOperationException('handler must be configured to build an AuthenticationScheme.')
        return AuthenticationScheme(self.name, self.handler)
