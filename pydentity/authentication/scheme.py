from pydentity.authentication.abc import IAuthenticationHandler


class AuthenticationScheme:
    def __init__(self, name: str, handler: IAuthenticationHandler):
        self.name = name
        self.handler = handler
