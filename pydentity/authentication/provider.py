from pydentity.authentication.abc import IAuthenticationSchemeProvider
from pydentity.authentication.scheme import AuthenticationScheme


class AuthenticationSchemeProvider(IAuthenticationSchemeProvider):
    schemes: dict[str, AuthenticationScheme] = {}

    async def get_scheme(self, name: str) -> AuthenticationScheme | None:
        return self.schemes.get(name, None)
