import inspect
from collections.abc import Iterable
from typing import Any, Optional, overload, Generator

from pydentity.exc import ArgumentNoneException
from pydentity.types import Predicate
from pydentity.utils import is_none_or_empty
from .claim_types import ClaimTypes
from .claim_value_types import ClaimValueTypes


class Claim:
    def __init__(
            self,
            claim_type: str,
            claim_value: str,
            value_type: Optional[str] = None,
            issuer: Optional[str] = None,
            original_issuer: Optional[str] = None,
            subject: Optional["ClaimsIdentity"] = None
    ) -> None:
        self._type = claim_type
        self._value = claim_value
        self._value_type = ClaimValueTypes.String if is_none_or_empty(value_type) else value_type
        self._issuer = ClaimsIdentity.DEFAULT_ISSUER if is_none_or_empty(issuer) else issuer
        self._original_issuer = self._issuer if is_none_or_empty(original_issuer) else original_issuer
        self._subject = subject

    @property
    def type(self) -> str:
        return self._type

    @property
    def value(self) -> str:
        return self._value

    @property
    def value_type(self) -> str:
        return self._value_type

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def original_issuer(self) -> str:
        return self._original_issuer

    @property
    def subject(self) -> Optional["ClaimsIdentity"]:
        return self._subject

    def clone(self, identity: Optional["ClaimsIdentity"] = None):
        return Claim(
            claim_type=self._type,
            claim_value=self._value,
            value_type=self._value_type,
            issuer=self._issuer,
            original_issuer=self._original_issuer,
            subject=identity
        )

    def dump(self):
        return {
            "claim_type": self.type,
            "claim_value": self.value,
            "value_type": self.value_type,
            "issuer": self.issuer,
            "original_issuer": self.original_issuer
        }

    @staticmethod
    def from_dict(data):
        return Claim(
            claim_type=data["claim_type"],
            claim_value=data["claim_value"],
            value_type=data["value_type"],
            issuer=data["issuer"],
            original_issuer=data["original_issuer"]
        )

    def __repr__(self) -> str:
        return f"{self.type}:{self.value}"


class ClaimsIdentity:
    DEFAULT_ISSUER = "LOCAL AUTHORITY"
    DEFAULT_NAME_CLAIM_TYPE = ClaimTypes.Name
    DEFAULT_ROLE_CLAIM_TYPE = ClaimTypes.Role

    def __init__(
            self,
            identity: Optional["ClaimsIdentity"] = None,
            claims: Optional[Iterable[Claim]] = None,
            authentication_type: Optional[str] = None,
            name_type: Optional[str] = None,
            role_type: Optional[str] = None
    ):

        if identity is not None and is_none_or_empty(authentication_type):
            self._authentication_type = identity.authentication_type
        else:
            self._authentication_type = authentication_type

        if not is_none_or_empty(name_type):
            self._name_claim_type = name_type
        elif identity is not None:
            self._name_claim_type = identity._name_claim_type
        else:
            self._name_claim_type = ClaimsIdentity.DEFAULT_NAME_CLAIM_TYPE

        if not is_none_or_empty(role_type):
            self._role_claim_type = role_type
        elif identity is not None:
            self._role_claim_type = identity._name_claim_type
        else:
            self._role_claim_type = ClaimsIdentity.DEFAULT_ROLE_CLAIM_TYPE

        self.__instance_claims: list[Claim] = []

        if identity is not None:
            self.add_claims(*identity.__instance_claims)

        if claims is not None:
            self.add_claims(*claims)

    @property
    def name(self) -> Optional[str]:
        return self.find_first_value(ClaimTypes.Name)

    @property
    def is_authenticated(self) -> bool:
        return not is_none_or_empty(self._authentication_type)

    @property
    def authentication_type(self) -> Optional[str]:
        return self._authentication_type

    @property
    def name_claim_type(self) -> Optional[str]:
        return self._name_claim_type

    @property
    def role_claim_type(self) -> Optional[str]:
        return self._role_claim_type

    @property
    def claims(self) -> Generator[Claim, Any, None]:
        for claim in self.__instance_claims:
            yield claim

    def add_claims(self, *claims: Claim):
        for claim in claims:
            if claim.subject is self:
                self.__instance_claims.append(claim)
            else:
                self.__instance_claims.append(claim.clone(self))

    def remove_claim(self, claim: Claim) -> bool:
        if claim is None:
            return False

        for i, _claim in enumerate(self.__instance_claims):
            if _claim is claim:
                self.__instance_claims.pop(i)
                return True

        return False

    @overload
    def find_all(self, claim_type: str) -> Generator[Claim, Any, None]:
        ...

    @overload
    def find_all(self, _match: Predicate[Claim]) -> Generator[Claim, Any, None]:
        ...

    def find_all(self, *args) -> Generator[Claim, Any, None]:
        if inspect.isfunction(args[0]):
            _match: Predicate[Claim] = args[0]
        else:
            def _match(x: Claim):
                return x is not None and x.type == args[0]

        for claim in self.claims:
            if _match(claim):
                yield claim

    @overload
    def find_first(self, claim_type: str) -> Optional[Claim]:
        ...

    @overload
    def find_first(self, _match: Predicate[Claim]) -> Optional[Claim]:
        ...

    def find_first(self, *args) -> Optional[Claim]:
        if inspect.isfunction(args[0]):
            _match: Predicate[Claim] = args[0]
        else:
            def _match(x: Claim):
                return x is not None and x.type == args[0]

        for claim in self.claims:
            if _match(claim):
                return claim

        return None

    @overload
    def find_first_value(self, claim_type: str, /) -> Optional[str]:
        ...

    @overload
    def find_first_value(self, _match: Predicate[Claim], /) -> Optional[str]:
        ...

    def find_first_value(self, *args) -> Optional[str]:
        if claim := self.find_first(*args):
            return claim.value
        return None

    @overload
    def has_claim(self, _match: Predicate[Claim], /) -> bool:
        ...

    @overload
    def has_claim(self, claim_type: str, claim_value: str, /) -> bool:
        ...

    def has_claim(self, *args) -> bool:
        if inspect.isfunction(args[0]):
            _match: Predicate[Claim] = args[0]
        else:
            _type, _value = args

            def _match(x: Claim):
                return (
                        x is not None and
                        x.type.casefold() == _type.casefold() and
                        x.value == _value
                )

        for claim in self.claims:
            if _match(claim):
                return True

        return False

    def clone(self):
        return ClaimsIdentity(identity=self)

    def dump(self):
        return {
            "authentication_type": self.authentication_type,
            "name_type": self._name_claim_type,
            "role_type": self.role_claim_type,
            "claims": [claim.dump() for claim in self.claims]
        }

    @staticmethod
    def from_dict(data):
        identity = ClaimsIdentity(
            authentication_type=data["authentication_type"],
            name_type=data["name_type"],
            role_type=data["role_type"],
        )
        identity.add_claims(
            *[Claim.from_dict(claim_dict) for claim_dict in data["claims"]]
        )
        return identity


class ClaimsPrincipal:
    def __init__(self, *identities: ClaimsIdentity):
        self._identities: list[ClaimsIdentity] = []
        if identities is not None:
            self._identities.extend(identities)

    @property
    def identities(self) -> tuple[ClaimsIdentity, ...]:
        return tuple(self._identities)

    @property
    def identity(self) -> ClaimsIdentity | None:
        return self.select_primary_identity(self._identities)

    @property
    def claims(self) -> Generator[Claim, Any, None]:
        for identity in self._identities:
            if identity is not None:
                for claim in identity.claims:
                    yield claim

    @overload
    def find_all(self, claim_type: str, /) -> Generator[Claim, Any, None]:
        ...

    @overload
    def find_all(self, _match: Predicate[Claim], /) -> Generator[Claim, Any, None]:
        ...

    def find_all(self, *args) -> Generator[Claim, Any, None]:
        if inspect.isfunction(args[0]):
            _match: Predicate[Claim] = args[0]
        else:
            def _match(x: Claim):
                return x is not None and x.type == args[0]

        for identity in self._identities:
            if identity is not None:
                for claim in identity.find_all(_match):
                    yield claim

    @overload
    def find_first(self, claim_type: str, /) -> Optional[Claim]:
        ...

    @overload
    def find_first(self, _match: Predicate[Claim], /) -> Optional[Claim]:
        ...

    def find_first(self, *args) -> Optional[Claim]:
        if inspect.isfunction(args[0]):
            _match: Predicate[Claim] = args[0]
        else:
            def _match(x):
                return x is not None and x.type == args[0]

        for identity in self._identities:
            claim = identity.find_first(_match)
            if claim is not None:
                return claim

        return None

    @overload
    def find_first_value(self, claim_type: str, /) -> Optional[str]:
        ...

    @overload
    def find_first_value(self, _match: Predicate[Claim], /) -> Optional[str]:
        ...

    def find_first_value(self, *args) -> Optional[str]:
        if claim := self.find_first(*args):
            return claim.value
        return None

    @overload
    def has_claim(self, _match: Predicate[Claim], /) -> bool:
        ...

    @overload
    def has_claim(self, claim_type: str, claim_value: Any, /) -> bool:
        ...

    def has_claim(self, *args) -> bool:
        if inspect.isfunction(args[0]):
            _match: Predicate[Claim] = args[0]
        else:
            _type, _value = args

            def _match(x: Claim):
                return (
                        x is not None and
                        x.type.casefold() == _type.casefold() and
                        x.value == _value
                )

        for identity in self._identities:
            if identity.has_claim(_match):
                return True

        return False

    def select_primary_identity(self, identities: Iterable[ClaimsIdentity]) -> Optional[ClaimsIdentity]:  # noqa
        if identities is None:
            raise ArgumentNoneException("identities")

        for identity in identities:
            if identity is not None:
                return identity

        return None

    def add_identities(self, *identities: ClaimsIdentity):
        if identities is None:
            raise ArgumentNoneException("identities")
        self._identities.extend(identities)

    def is_in_role(self, role: str) -> bool:
        for _identity in self._identities:
            if _identity is not None:
                if _identity.has_claim(_identity.role_claim_type, role):
                    return True

        return False

    def is_in_all_roles(self, *roles: str) -> bool:
        if not roles:
            return False

        for role in roles:
            if not self.is_in_role(role):
                return False

        return True

    def is_in_any_role(self, *roles: str):
        if not roles:
            return False

        for role in roles:
            if self.is_in_role(role):
                return True

        return False

    def dump(self) -> list[dict]:
        return [i.dump() for i in self._identities]

    @staticmethod
    def from_list(data: list[dict]):
        return ClaimsPrincipal(*[ClaimsIdentity.from_dict(identity_dict) for identity_dict in data])
