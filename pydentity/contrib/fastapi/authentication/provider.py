from pydentity.contrib.fastapi.authentication.abc import IAuthenticationSchemeProvider
from pydentity.contrib.fastapi.authentication.options import AuthenticationOptions
from pydentity.contrib.fastapi.authentication.scheme import AuthenticationScheme
from pydentity.exc import ArgumentNoneException


class AuthenticationSchemeProvider(IAuthenticationSchemeProvider):
    options: AuthenticationOptions = {}

    async def get_scheme(self, name: str) -> AuthenticationScheme | None:
        if not name:
            raise ArgumentNoneException('name')

        return getattr(self.options, '_policy_map').get(name, None)
