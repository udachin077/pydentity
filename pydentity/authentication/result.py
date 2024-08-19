from pydentity.security.claims import ClaimsPrincipal


class AuthenticationResult:
    def __init__(self, principal: ClaimsPrincipal, properties: dict):
        self._principal = principal
        self._properties = properties

    @property
    def principal(self):
        return self._principal

    @property
    def properties(self):
        return self._properties
