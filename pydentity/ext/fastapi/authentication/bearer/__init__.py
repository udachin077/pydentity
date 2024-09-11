import logging
from collections.abc import Iterable, Generator
from datetime import timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jwt.exceptions import PyJWTError, InvalidKeyError, ExpiredSignatureError

from pydentity.authentication import AuthenticationResult
from pydentity.authentication.abc import IAuthenticationHandler
from pydentity.http.context import HttpContext
from pydentity.security.claims import ClaimsPrincipal, ClaimsIdentity, Claim
from pydentity.utils import datetime, islist

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


def _generate_claims(payload: dict[str, Any]) -> Generator[Claim]:
    for key, value in payload.items():
        if key in ("aud", "exp", "iat", "iss", "jti", "nbf", "sub",):
            continue

        if islist(value):
            yield from (Claim(key, v) for v in value)
        else:
            yield Claim(key, value)


def _create_principal_from_jwt(token: "JWTSecurityToken") -> ClaimsPrincipal:
    identity = ClaimsIdentity("AuthenticationTypes.Federation")
    if token.claims:
        identity.add_claims(*token.claims)
    return ClaimsPrincipal(identity)


class JWTSecurityToken(dict[str, Any]):
    def __init__(
            self,
            signin_key: _KeyType,
            algorithm: str = "HS256",
            audience: str | None = None,
            claims: Iterable[Claim] | None = None,
            expires: datetime | int | None = None,
            headers: dict[str, Any] | None = None,
            issuer: str | None = None,
            issuer_at: datetime | int | None = None,
            not_before: datetime | int | None = None,
            subject: str | None = None,
            **kwargs
    ) -> None:
        super().__init__()
        self.__signing_key = signin_key
        self.algorithm = algorithm
        self.headers = headers
        self.claims = claims
        self.update(kwargs)
        self.expires = expires
        self.not_before = not_before
        self.audience = audience
        self.issuer = issuer
        self.issuer_at = issuer_at
        self.subject = subject

    @property
    def audience(self) -> str | None:
        return self.get("aud")

    @audience.setter
    def audience(self, value: str | None) -> None:
        self._set_or_remove("aud", value)

    @property
    def expires(self) -> datetime | int | None:
        return self.get("exp")

    @expires.setter
    def expires(self, value: datetime | int | None) -> None:
        self._set_or_remove("exp", value)

    @property
    def issuer(self) -> str | None:
        return self.get("iss")

    @issuer.setter
    def issuer(self, value: str | None) -> None:
        self._set_or_remove("iss", value)

    @property
    def issuer_at(self) -> datetime | int | None:
        return self.get("iat")

    @issuer_at.setter
    def issuer_at(self, value: datetime | int | None) -> None:
        self._set_or_remove("iat", value)

    @property
    def not_before(self) -> datetime | int | None:
        return self.get("nbf")

    @not_before.setter
    def not_before(self, value: datetime | int | None) -> None:
        self._set_or_remove("nbf", value)

    @property
    def subject(self) -> str | None:
        return self.get("sub")

    @subject.setter
    def subject(self, value: str | None) -> None:
        self._set_or_remove("sub", value)

    def _set_or_remove(self, key: str, value: Any) -> None:
        if value is not None:
            self[key] = value
        elif key in self:
            del self[key]

    def _set_claims(self) -> None:
        for claim in self.claims:
            if value := self.get(claim.type):
                if islist(value):
                    self[claim.type].append(claim.value)
                else:
                    self[claim.type] = [value, claim.value]
            else:
                self[claim.type] = claim.value

    def encode(self) -> str:
        if self.expires and self.not_before and self.not_before >= self.expires:
            raise ExpiredSignatureError(f"Expires: '{self.expires}' must be after not_before: '{self.not_before}'.")

        if not self.__signing_key:
            raise InvalidKeyError()

        if self.claims:
            self._set_claims()

        return jwt.encode(self, self.__signing_key, self.algorithm, self.headers)

    @staticmethod
    def decode(
            token: str | bytes,
            key: _KeyType,
            algorithms: list[str] | None = None,
            options: dict[str, Any] | None = None,
            audience: str | Iterable[str] | None = None,
            issuer: str | list[str] | None = None,
            leeway: float | timedelta = 0
    ):
        payload = jwt.decode(
            token,
            key,
            algorithms=algorithms or ["HS256"],
            audience=audience,
            issuer=issuer,
            options=options,
            leeway=leeway
        )

        return JWTSecurityToken(
            signin_key=key,
            claims=[*_generate_claims(payload)] or None,
            **payload
        )


class TokenValidationParameters:
    __slots__ = (
        "issuer_signing_key",
        "leeway",
        "options",
        "valid_algorithms",
        "valid_audiences",
        "valid_issuers",
    )

    def __init__(
            self,
            issuer_signing_key: _KeyType,
            valid_algorithms: list[str] | None = None,
            valid_audiences: str | Iterable[str] | None = None,
            valid_issuers: str | list[str] | None = None,
            options: dict[str, Any] | None = None,
            leeway: float | timedelta = 0
    ) -> None:
        self.issuer_signing_key = issuer_signing_key
        self.valid_algorithms = valid_algorithms or ["HS256"]
        self.valid_audiences = valid_audiences
        self.valid_issuers = valid_issuers
        self.options = options
        self.leeway = leeway


class JWTBearerAuthenticationHandler(IAuthenticationHandler):
    __slots__ = ("_tvp", "_logger",)

    def __init__(self, validation_parameters: TokenValidationParameters) -> None:
        self._tvp = validation_parameters
        self._logger = logging.getLogger(self.__class__.__name__)

    async def authenticate(self, context: HttpContext, scheme: str) -> AuthenticationResult:
        authorization = context.request.headers.get("Authorization")
        scheme, token = _get_authorization_scheme_param(authorization)

        if not authorization or scheme.lower() != "bearer":
            self._logger.info("Invalid Authorization header: Bearer.")
            return AuthenticationResult(ClaimsPrincipal(), {})

        try:
            jwt_token = JWTSecurityToken.decode(
                token,
                key=self._tvp.issuer_signing_key,
                algorithms=self._tvp.valid_algorithms,
                audience=self._tvp.valid_audiences,
                issuer=self._tvp.valid_issuers,
                options=self._tvp.options,
                leeway=self._tvp.leeway
            )
            return AuthenticationResult(_create_principal_from_jwt(jwt_token), {})

        except PyJWTError as ex:
            self._logger.error(str(ex))
            return AuthenticationResult(ClaimsPrincipal(), {})

    async def sign_in(self, context: HttpContext, scheme: str, principal: ClaimsPrincipal, **properties) -> None:
        pass

    async def sign_out(self, context: HttpContext, scheme: str) -> None:
        pass
