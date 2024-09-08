from collections.abc import Iterable, Generator
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jwt.exceptions import PyJWTError

from pydentity.authentication._base import AuthenticationResult, AuthenticationError
from pydentity.authentication.abc import IAuthenticationHandler
from pydentity.exc import ArgumentNoneException
from pydentity.http.context import HttpContext
from pydentity.security.claims import ClaimsPrincipal, ClaimsIdentity, Claim
from pydentity.utils import datetime

__all__ = (
    "JWTBearerAuthenticationHandler",
    "JWTSecurityToken",
    "TokenValidationParameters",
)

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
        "claims",
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
            claims: Iterable[Claim] | None = None,
            issuer_at: datetime | int | None = None,
            headers: dict[str, Any] | None = None,
    ):
        self.algorithm = algorithm
        self.audience = audience
        self.expires = expires
        self.headers = headers
        self.issuer = issuer
        self.issuer_at = issuer_at
        self.claims = claims
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

        if self.claims:
            self._set_claims(payload)

        return jwt.encode(payload, self.signing_key, self.algorithm, self.headers)

    def _set_claims(self, payload: dict[str, Any]) -> None:
        for claim in self.claims:
            if claim_value := payload.get(claim.type):
                if isinstance(claim_value, list):
                    payload[claim.type].append(claim.value)
                else:
                    payload[claim.type] = [claim_value, claim.value]
            else:
                payload[claim.type] = claim.value


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
    ) -> None:
        if not issuer_signing_key:
            raise ArgumentNoneException("issuer_signing_key")

        self.issuer_signing_key = issuer_signing_key
        self.valid_algorithms = valid_algorithms or ["HS256"]
        self.valid_audiences = valid_audiences
        self.valid_issuers = valid_issuers


class JWTBearerAuthenticationHandler(IAuthenticationHandler):
    __slots__ = ("validation_parameters",)

    def __init__(
            self,
            validation_parameters: TokenValidationParameters | None = None,
    ) -> None:
        self.validation_parameters = validation_parameters or TokenValidationParameters("")

    async def authenticate(self, context: HttpContext, scheme: str) -> AuthenticationResult:
        authorization = context.request.headers.get("Authorization")
        scheme, token = _get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            raise AuthenticationError()

        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                key=self.validation_parameters.issuer_signing_key,
                algorithms=self.validation_parameters.valid_algorithms,
                audience=self.validation_parameters.valid_audiences,
                issuer=self.validation_parameters.valid_issuers
            )
            return AuthenticationResult(self._create_principal(payload), {})
        except PyJWTError:
            return AuthenticationResult(ClaimsPrincipal(), {})

    async def sign_in(self, context: HttpContext, scheme: str, principal: ClaimsPrincipal, **properties) -> None:
        pass

    async def sign_out(self, context: HttpContext, scheme: str) -> None:
        pass

    def _generate_claims(self, payload: dict[str, Any]) -> Generator[Claim]:  # noqa
        base_claims = ("iss", "sub", "aud", "exp", "nbf", "iat", "jti",)

        for key, value in payload.items():
            if key in base_claims:
                continue

            if isinstance(value, list):
                yield from (Claim(key, c) for c in value)
            else:
                yield Claim(key, value)

    def _create_principal(self, payload: dict[str, Any]) -> ClaimsPrincipal:
        identity = ClaimsIdentity(
            "AuthenticationTypes.Federation",
            *self._generate_claims(payload)
        )
        return ClaimsPrincipal(identity)
