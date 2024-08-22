from pydentity.contrib.fastapi.authentication.abc import IAuthenticationHandler
from pydentity.exc import InvalidOperationException, ArgumentNoneException


class AuthenticationScheme:
    __slots__ = ('name', 'handler',)

    def __init__(self, name: str, handler: IAuthenticationHandler):
        if not name:
            raise ArgumentNoneException('name')
        if not handler:
            raise ArgumentNoneException('handler')

        self.name = name
        self.handler = handler


class AuthenticationSchemeBuilder:

    def __init__(self, name: str, handler: IAuthenticationHandler = None):
        self.name = name
        self.handler = handler

    def build(self):
        if not self.handler:
            raise InvalidOperationException('handler must be configured to build an AuthenticationScheme.')
        return AuthenticationScheme(self.name, self.handler)
