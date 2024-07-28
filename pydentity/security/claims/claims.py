from collections.abc import Iterable
from copy import deepcopy
from inspect import isfunction
from typing import Any, Generator, Final, overload, Literal

from pydentity.exc import ArgumentNoneException
from pydentity.security.claims.claim_types import ClaimTypes
from pydentity.types import Predicate


class Claim:
    __slots__ = ('_type', '_value')

    def __init__(self, claim_type: str, claim_value: Any):
        self._type = claim_type
        self._value = claim_value

    @property
    def type(self) -> str:
        return self._type

    @property
    def value(self) -> Any:
        return self._value

    def clone(self):
        return deepcopy(self)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} {self.type}:{self.value} at {id(self)}>'

    def __eq__(self, other):
        if not isinstance(other, Claim):
            raise TypeError('the operand must be of type Claim')
        if self.type == other.type and self.value == other.value:
            return True
        return False


class ClaimsIdentity:
    __slots__ = ('_authentication_type', '_claims', '_name_claim_type', '_role_claim_type',)

    DEFAULT_ISSUER: Final[str] = 'LOCAL AUTHORITY'
    DEFAULT_NAME_CLAIM_TYPE: Final[str] = ClaimTypes.Name
    DEFAULT_ROLE_CLAIM_TYPE: Final[str] = ClaimTypes.Role

    def __init__(
            self,
            authentication_type: str | None = None,
            *claims: Claim,
            name_claim_type: str = ClaimTypes.Name,
            role_claim_type: str = ClaimTypes.Role
    ):
        self._authentication_type = authentication_type
        self._claims = list(claims) or []
        self._name_claim_type = name_claim_type
        self._role_claim_type = role_claim_type

    @property
    def name(self) -> str | None:
        return self.find_first_value(ClaimTypes.Name)

    @property
    def is_authenticated(self) -> bool:
        return bool(self._authentication_type)

    @property
    def authentication_type(self) -> str | None:
        return self._authentication_type

    @property
    def name_claim_type(self) -> str | None:
        return self._name_claim_type

    @property
    def role_claim_type(self) -> str | None:
        return self._role_claim_type

    @property
    def claims(self) -> Generator[Claim, Any, None]:
        for claim in self._claims:
            yield claim

    def add_claims(self, *claims: Claim):
        if not claims:
            raise ArgumentNoneException('claims')
        self._claims.extend(claims)

    def remove_claim(self, claim: Claim) -> bool:
        if not claim:
            return False

        for i, _claim in enumerate(self._claims):
            if _claim == claim:
                self._claims.pop(i)
                return True

        return False

    @overload
    def find_all(self, claim_type: str) -> Generator[Claim, Any, None]:
        ...

    @overload
    def find_all(self, _match: Predicate[Claim]) -> Generator[Claim, Any, None]:
        ...

    def find_all(self, claim_type_or_match: str | Predicate[Claim]) -> Generator[Claim, Any, None]:
        if isfunction(claim_type_or_match):
            _match: Predicate[Claim] = claim_type_or_match
        else:
            def _match(x: Claim):
                return x and x.type == claim_type_or_match

        for claim in self.claims:
            if _match(claim):
                yield claim

    @overload
    def find_first(self, claim_type: str) -> Claim | None:
        ...

    @overload
    def find_first(self, _match: Predicate[Claim]) -> Claim | None:
        ...

    def find_first(self, claim_type_or_match: str | Predicate[Claim]) -> Claim | None:
        if isfunction(claim_type_or_match):
            _match: Predicate[Claim] = claim_type_or_match
        else:
            def _match(x: Claim):
                return x and x.type == claim_type_or_match

        for claim in self.claims:
            if _match(claim):
                return claim

        return None

    @overload
    def find_first_value(self, claim_type: str, /) -> str | None:
        ...

    @overload
    def find_first_value(self, _match: Predicate[Claim], /) -> str | None:
        ...

    def find_first_value(self, claim_type_or_match: str | Predicate[Claim]) -> str | None:
        if claim := self.find_first(claim_type_or_match):
            return claim.value
        return None

    @overload
    def has_claim(self, _match: Predicate[Claim], /) -> bool:
        ...

    @overload
    def has_claim(self, claim_type: str, claim_value: Any, /) -> bool:
        ...

    def has_claim(self, claim_type_or_match: str | Predicate[Claim], claim_value: Any = None) -> bool:
        if isfunction(claim_type_or_match):
            _match: Predicate[Claim] = claim_type_or_match
        else:
            _type = claim_type_or_match
            _value = claim_value

            def _match(x: Claim):
                return (
                        x and
                        x.type.casefold() == _type.casefold() and
                        x.value == _value
                )

        for claim in self.claims:
            if _match(claim):
                return True

        return False


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
            for claim in identity.claims:
                yield claim

    @overload
    def find_all(self, claim_type: str, /) -> Generator[Claim, Any, None]:
        ...

    @overload
    def find_all(self, _match: Predicate[Claim], /) -> Generator[Claim, Any, None]:
        ...

    def find_all(self, claim_type_or_match: str | Predicate[Claim]) -> Generator[Claim, Any, None]:
        if isfunction(claim_type_or_match):
            _match: Predicate[Claim] = claim_type_or_match
        else:
            def _match(x: Claim):
                return x and x.type == claim_type_or_match

        for identity in self._identities:
            for claim in identity.find_all(_match):
                yield claim

    @overload
    def find_first(self, claim_type: str, /) -> Claim | None:
        ...

    @overload
    def find_first(self, _match: Predicate[Claim], /) -> Claim | None:
        ...

    def find_first(self, claim_type_or_match: str | Predicate[Claim]) -> Claim | None:
        if isfunction(claim_type_or_match):
            _match: Predicate[Claim] = claim_type_or_match
        else:
            def _match(x):
                return x and x.type == claim_type_or_match

        for identity in self._identities:
            if claim := identity.find_first(_match):
                return claim
        return None

    @overload
    def find_first_value(self, claim_type: str, /) -> str | None:
        ...

    @overload
    def find_first_value(self, _match: Predicate[Claim], /) -> str | None:
        ...

    def find_first_value(self, claim_type_or_match: str | Predicate[Claim]) -> str | None:
        if claim := self.find_first(claim_type_or_match):
            return claim.value
        return None

    @overload
    def has_claim(self, _match: Predicate[Claim], /) -> bool:
        ...

    @overload
    def has_claim(self, claim_type: str, claim_value: Any, /) -> bool:
        ...

    def has_claim(self, claim_type_or_match: str | Predicate[Claim], claim_value: Any = None) -> bool:
        if isfunction(claim_type_or_match):
            _match: Predicate[Claim] = claim_type_or_match
        else:
            _type = claim_type_or_match
            _value = claim_value

            def _match(x: Claim):
                return (
                        x and
                        x.type.casefold() == _type.casefold() and
                        x.value == _value
                )

        for identity in self._identities:
            if identity.has_claim(_match):
                return True
        return False

    def select_primary_identity(self, identities: Iterable[ClaimsIdentity]) -> ClaimsIdentity | None:
        if not identities:
            raise ArgumentNoneException('identities')
        for identity in identities:
            return identity
        return None

    def add_identities(self, *identities: ClaimsIdentity):
        if not identities:
            raise ArgumentNoneException('identities')
        self._identities.extend(identities)

    def is_in_role(self, role: str) -> bool:
        for _identity in self._identities:
            if _identity.has_claim(_identity.role_claim_type, role):
                return True
        return False

    def is_in_roles(self, *roles: str, mode: Literal['all', 'any'] = 'all') -> bool:
        if not roles:
            return False

        if mode == 'all':
            for role in roles:
                if not self.is_in_role(role):
                    return False
            return True
        elif mode == 'any':
            for role in roles:
                if self.is_in_role(role):
                    return True
            return False
        else:
            raise ValueError('mode')
