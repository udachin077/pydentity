from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jwt.exceptions import PyJWTError

from pydentity.authentication._base import AuthenticationResult, AuthenticationError
from pydentity.authentication.abc import IAuthenticationHandler
from pydentity.http.context import HttpContext
from pydentity.security.claims import ClaimsPrincipal, ClaimTypes
from pydentity.security.claims.serializer import ClaimsPrincipalSerializer
from pydentity.utils import datetime

_KeyType = RSAPrivateKey | EllipticCurvePrivateKey | Ed25519PrivateKey | Ed448PrivateKey | str | bytes


def _get_authorization_scheme_param(authorization_header_value: str | None) -> tuple[str, str]:
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param


class JWTSecurityToken:
    __slots__ = (
        "algorithm",
        "audience",
        "expires",
        "headers",
        "issuer",
        "issuer_at",
        "principal",
        "signing_key",
        "subject",
    )

    def __init__(
            self,
            signin_key: _KeyType,
            algorithm: str = "HS256",
            audience: str | None = None,
            issuer: str | None = None,
            subject: str | None = None,
            expires: datetime | int = datetime.utcnow().add_hours(1),
            principal: ClaimsPrincipal | None = None,
            issuer_at: datetime | int | None = None,
            headers: dict[str, Any] | None = None
    ):
        self.algorithm = algorithm
        self.audience = audience
        self.expires = expires
        self.headers = headers
        self.issuer = issuer
        self.issuer_at = issuer_at
        self.principal = principal
        self.signing_key = signin_key
        self.subject = subject

    def encode(self) -> str:
        payload = {"exp": self.expires}

        if self.audience:
            payload["aud"] = self.audience

        if self.issuer:
            payload["iss"] = self.issuer

        if self.issuer_at:
            payload["iat"] = self.issuer_at

        if self.subject:
            payload["sub"] = self.subject
        elif self.principal:
            if identifier := self.principal.find_first_value(ClaimTypes.NameIdentifier):
                payload["sub"] = identifier

        if self.principal:
            payload["claims"] = ClaimsPrincipalSerializer.serialize(self.principal)
            payload["roles"] = [role for role in self.principal.find_all(ClaimTypes.Role)]

        return jwt.encode(payload, self.signing_key, self.algorithm, self.headers)


class TokenValidationParameters:
    __slots__ = (
        "issuer_signing_key",
        "valid_algorithms",
        "valid_audiences",
        "valid_issuers",
    )

    def __init__(
            self,
            issuer_signing_key: _KeyType,
            valid_algorithms: list[str] | None = None,
            valid_audiences: list[str] | None = None,
            valid_issuers: list[str] | None = None
    ):
        self.issuer_signing_key = issuer_signing_key
        self.valid_algorithms = valid_algorithms or ["HS256"]
        self.valid_audiences = valid_audiences
        self.valid_issuers = valid_issuers


class JWTBearerAuthenticationHandler(IAuthenticationHandler):
    __slots__ = ("validation_parameters",)

    def __init__(self, validation_parameters: TokenValidationParameters | None = None):
        self.validation_parameters = validation_parameters or TokenValidationParameters("")

    async def authenticate(self, context: HttpContext, scheme: str) -> AuthenticationResult:
        authorization = context.request.headers.get("Authorization")
        scheme, token = _get_authorization_scheme_param(authorization)

        if not authorization or scheme.lower() != "bearer":
            raise AuthenticationError()

        try:
            payload = jwt.decode(
                token,
                key=self.validation_parameters.issuer_signing_key,
                algorithms=self.validation_parameters.valid_algorithms,
                audience=self.validation_parameters.valid_audiences,
                issuer=self.validation_parameters.valid_issuers
            )
            principal = ClaimsPrincipalSerializer.deserialize(payload["claims"])
            return AuthenticationResult(principal, {})

        except PyJWTError:
            return AuthenticationResult(ClaimsPrincipal(), {})

    async def sign_in(self, context: HttpContext, scheme: str, principal: ClaimsPrincipal, **properties) -> None:
        pass

    async def sign_out(self, context: HttpContext, scheme: str) -> None:
        pass
