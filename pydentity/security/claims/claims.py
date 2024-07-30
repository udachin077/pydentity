from collections.abc import Iterable, Generator
from inspect import isfunction
from typing import Any, Final, Literal, overload

from pydentity.exc import ArgumentNoneException
from pydentity.security.claims.claim_types import ClaimTypes
from pydentity.types import Predicate


class Claim:
    __slots__ = ('_type', '_value')

    def __init__(self, claim_type: str, claim_value: Any) -> None:
        if not claim_type:
            raise ArgumentNoneException('claim_type')
        if not claim_value:
            raise ArgumentNoneException('claim_value')

        self._type = claim_type
        self._value = claim_value

    @property
    def type(self) -> str:
        return self._type

    @property
    def value(self) -> Any:
        return self._value

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} {self.type}:{self.value} at {id(self)}>'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Claim):
            raise TypeError('the operand must be of type Claim')
        return self.type == other.type and self.value == other.value

    def __hash__(self) -> int:
        return hash(f'{self.type}:{self.value}')


class ClaimsIdentity:
    __slots__ = ('_authentication_type', '_claims', '_name_claim_type', '_role_claim_type',)

    DEFAULT_NAME_CLAIM_TYPE: Final[str] = ClaimTypes.Name
    DEFAULT_ROLE_CLAIM_TYPE: Final[str] = ClaimTypes.Role

    def __init__(
            self,
            authentication_type: str | None = None,
            *claims: Claim,
            name_claim_type: str | None = None,
            role_claim_type: str | None = None
    ) -> None:
        self._authentication_type = authentication_type
        self._name_claim_type: str = name_claim_type or self.DEFAULT_NAME_CLAIM_TYPE
        self._role_claim_type: str = role_claim_type or self.DEFAULT_ROLE_CLAIM_TYPE
        self._claims: set[Claim] = set(claims) if claims else set()

    @property
    def name(self) -> str | None:
        return self.find_first_value(self._name_claim_type)

    @property
    def is_authenticated(self) -> bool:
        return bool(self._authentication_type)

    @property
    def authentication_type(self) -> str | None:
        return self._authentication_type

    @property
    def name_claim_type(self) -> str:
        return self._name_claim_type

    @property
    def role_claim_type(self) -> str:
        return self._role_claim_type

    @property
    def claims(self) -> Generator[Claim]:
        for claim in self._claims:
            yield claim

    def add_claims(self, *claims: Claim) -> None:
        if not claims:
            raise ArgumentNoneException('claims')
        self._claims.update(claims)

    def remove_claim(self, claim: Claim) -> None:
        if not claim:
            raise ArgumentNoneException('claim')
        self._claims.remove(claim)

    @overload
    def find_all(self, claim_type: str, /) -> Generator[Claim]:
        """
        Retrieves a Claim`s where each Claim.type equals claim_type.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    @overload
    def find_all(self, _match: Predicate[Claim], /) -> Generator[Claim]:
        """
        Retrieves a Claim`s where each claim is matched by match.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    def find_all(self, claim_type_or_match: str | Predicate[Claim]) -> Generator[Claim]:
        if isfunction(claim_type_or_match):
            _match: Predicate[Claim] = claim_type_or_match
        else:
            def _match(x: Claim) -> bool:
                return x and x.type == claim_type_or_match  # type: ignore

        for claim in self.claims:
            if _match(claim):
                yield claim

    @overload
    def find_first(self, claim_type: str, /) -> Claim | None:
        """
        Retrieves the first Claim`s where the Claim.type equals claim_type.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    @overload
    def find_first(self, _match: Predicate[Claim], /) -> Claim | None:
        """
        Retrieves the first Claim`s that is matched by match.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    def find_first(self, claim_type_or_match: str | Predicate[Claim]) -> Claim | None:
        if isfunction(claim_type_or_match):
            _match: Predicate[Claim] = claim_type_or_match
        else:
            def _match(x: Claim) -> bool:
                return x and x.type == claim_type_or_match  # type: ignore

        for claim in self.claims:
            if _match(claim):
                return claim

        return None

    @overload
    def find_first_value(self, claim_type: str, /) -> str | None:
        """
        Return the claim value for the first claim with the specified claim_type if it exists, null otherwise

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    @overload
    def find_first_value(self, _match: Predicate[Claim], /) -> str | None:
        """
        Return the claim value for the first claim with the specified match if it exists, null otherwise

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    def find_first_value(self, claim_type_or_match: str | Predicate[Claim]) -> str | None:
        if claim := self.find_first(claim_type_or_match):
            return claim.value

        return None

    @overload
    def has_claim(self, _match: Predicate[Claim], /) -> bool:
        """
        Determines if a claim is contained within all the ClaimsIdentities in this ClaimPrincipal.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def has_claim(self, claim_type: str, claim_value: Any, /) -> bool:
        """
        Determines if a claim of claim_type AND claim_value exists in any of the identities.

        :param claim_type: The type of the claim to match.
        :param claim_value:  The value of the claim to match.
        :return:
        """
        ...

    def has_claim(self, claim_type_or_match: str | Predicate[Claim], claim_value: Any = None) -> bool:
        if isfunction(claim_type_or_match):
            _match: Predicate[Claim] = claim_type_or_match
        else:
            assert isinstance(claim_type_or_match, str)
            _type: str = claim_type_or_match
            _value: Any = claim_value

            def _match(x: Claim) -> bool:
                return bool(x and x.type == _type and x.value == _value)

        for claim in self.claims:
            if _match(claim):
                return True

        return False

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} auth:{self.authentication_type} at {id(self)}>'


class ClaimsPrincipal:
    def __init__(self, *identities: ClaimsIdentity):
        self._identities: list[ClaimsIdentity] = list(identities) if identities else []

    @property
    def identities(self) -> tuple[ClaimsIdentity, ...]:
        return tuple(self._identities)

    @property
    def identity(self) -> ClaimsIdentity | None:
        return self.select_primary_identity(self._identities)

    @property
    def claims(self) -> Generator[Claim]:
        for identity in self._identities:
            for claim in identity.claims:
                yield claim

    @overload
    def find_all(self, claim_type: str, /) -> Generator[Claim]:
        """
        Retrieves a Claim`s where each Claim.type equals claim_type.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    @overload
    def find_all(self, _match: Predicate[Claim], /) -> Generator[Claim]:
        """
        Retrieves a Claim`s where each claim is matched by match.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    def find_all(self, claim_type_or_match: str | Predicate[Claim]) -> Generator[Claim]:
        if isfunction(claim_type_or_match):
            _match: Predicate[Claim] = claim_type_or_match
        else:
            assert isinstance(claim_type_or_match, str)

            def _match(x: Claim) -> bool:
                return bool(x and x.type == claim_type_or_match)

        for identity in self._identities:
            for claim in identity.find_all(_match):
                yield claim

    @overload
    def find_first(self, claim_type: str, /) -> Claim | None:
        """
        Retrieves the first Claim`s where the Claim.type equals claim_type.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    @overload
    def find_first(self, _match: Predicate[Claim], /) -> Claim | None:
        """
        Retrieves the first Claim`s that is matched by match.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    def find_first(self, claim_type_or_match: str | Predicate[Claim]) -> Claim | None:
        if isfunction(claim_type_or_match):
            _match: Predicate[Claim] = claim_type_or_match
        else:
            def _match(x: Claim) -> bool:
                return bool(x and x.type == claim_type_or_match)

        for identity in self._identities:
            if claim := identity.find_first(_match):
                return claim

        return None

    @overload
    def find_first_value(self, claim_type: str, /) -> str | None:
        """
        Return the claim value for the first claim with the specified claim_type if it exists, null otherwise

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    @overload
    def find_first_value(self, _match: Predicate[Claim], /) -> str | None:
        """
        Return the claim value for the first claim with the specified match if it exists, null otherwise

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    def find_first_value(self, claim_type_or_match: str | Predicate[Claim]) -> str | None:
        if claim := self.find_first(claim_type_or_match):
            return claim.value
        return None

    @overload
    def has_claim(self, _match: Predicate[Claim], /) -> bool:
        """
        Determines if a claim is contained within all the ClaimsIdentities in this ClaimPrincipal.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def has_claim(self, claim_type: str, claim_value: Any, /) -> bool:
        """
        Determines if a claim of claim_type AND claim_value exists in any of the identities.

        :param claim_type: The type of the claim to match.
        :param claim_value:  The value of the claim to match.
        :return:
        """
        ...

    def has_claim(self, claim_type_or_match: str | Predicate[Claim], claim_value: Any = None) -> bool:
        if isfunction(claim_type_or_match):
            _match: Predicate[Claim] = claim_type_or_match
        else:
            assert isinstance(claim_type_or_match, str)
            _type: str = claim_type_or_match
            _value: Any = claim_value

            def _match(x: Claim) -> bool:
                return bool(x and x.type == _type and x.value == _value)

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

    def add_identities(self, *identities: ClaimsIdentity) -> None:
        """
        Adds ClaimsIdentity to the internal list.

        :param identities:
        :return:
        """
        if not identities:
            raise ArgumentNoneException('identities')

        self._identities.extend(identities)

    def is_in_role(self, role: str) -> bool:
        """
        is_in_role answers the question: does an identity this principal possesses
        contain a claim of type role_claim_type where the value is '==' to the role.

        :param role: The role to check for.
        :return:
        """
        for _identity in self._identities:
            if _identity.has_claim(_identity.role_claim_type, role):
                return True
        return False

    def is_in_roles(self, *roles: str, mode: Literal['all', 'any'] = 'all') -> bool:
        """
        is_in_roles answers the question: does an identity this principal possesses
        contain a claim of type role_claim_type where the value is '==' to the roles.

        :param roles: The roles to check for.
        :param mode: Verification mode.
        :return:
        """
        if not roles:
            raise ArgumentNoneException('roles')

        match mode:
            case 'all':
                for role in roles:
                    if not self.is_in_role(role):
                        return False
                return True

            case 'any':
                for role in roles:
                    if self.is_in_role(role):
                        return True
                return False

            case _:
                raise ValueError('the "mode" must be "all" or "any"')
