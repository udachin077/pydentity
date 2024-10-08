from collections.abc import Iterable, Generator
from inspect import isfunction
from typing import Any, Final, Literal, overload, Optional

from pydentity.exc import ArgumentNoneException
from pydentity.security.claims.claim_types import ClaimTypes
from pydentity.types import Predicate


class Claim:
    __slots__ = ('_type', '_value', '_subject',)

    def __init__(self, claim_type: str, claim_value: Any, identity: Optional['ClaimsIdentity'] = None) -> None:
        if not claim_type:
            raise ArgumentNoneException('claim_type')
        if not claim_value:
            raise ArgumentNoneException('claim_value')

        self._type = claim_type
        self._value = claim_value
        self._subject = identity

    @property
    def type(self) -> str:
        return self._type

    @property
    def value(self) -> Any:
        return self._value

    @property
    def subject(self) -> Optional['ClaimsIdentity']:
        return self._subject

    def clone(self, identity: 'ClaimsIdentity') -> 'Claim':
        return Claim(self.type, self.value, identity)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} {self.type}:{self.value} at {id(self)}>'


class ClaimsIdentity:
    __slots__ = ('_authentication_type', '_claims', '_name_claim_type', '_role_claim_type',)

    DEFAULT_NAME_CLAIM_TYPE: Final[str] = ClaimTypes.Name
    DEFAULT_ROLE_CLAIM_TYPE: Final[str] = ClaimTypes.Role

    def __init__(
            self,
            authentication_type: Optional[str] = None,
            *claims: Claim,
            name_claim_type: Optional[str] = None,
            role_claim_type: Optional[str] = None
    ) -> None:
        self._authentication_type = authentication_type
        self._name_claim_type: str = name_claim_type or self.DEFAULT_NAME_CLAIM_TYPE
        self._role_claim_type: str = role_claim_type or self.DEFAULT_ROLE_CLAIM_TYPE
        self._claims: set[Claim] = set()
        if claims:
            self.add_claims(*claims)

    @property
    def name(self) -> Optional[str]:
        return self.find_first_value(self._name_claim_type)

    @property
    def is_authenticated(self) -> bool:
        return bool(self._authentication_type)

    @property
    def authentication_type(self) -> Optional[str]:
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
            return

        for claim in claims:
            if claim.subject is self:
                self._claims.add(claim)
            else:
                self._claims.add(claim.clone(self))

    def remove_claim(self, claim: Claim) -> None:
        if not claim:
            raise ArgumentNoneException('claim')
        self._claims.remove(claim)

    @overload
    def find_all(self, _match: Predicate[Claim], /) -> Generator[Claim]:
        """
        Retrieves a ``Claim``'s where match matches each claim.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def find_all(self, claim_type: str, /) -> Generator[Claim]:
        """
        Retrieves a ``Claim``'s where each ``claim_type`` equals claim_type.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    def find_all(self, _match) -> Generator[Claim]:
        if isfunction(_match):
            for claim in self.claims:
                if _match(claim):
                    yield claim
        elif isinstance(_match, str):
            yield from self.find_all(lambda c: bool(c and c.type == _match))
        else:
            raise NotImplemented

    @overload
    def find_first(self, _match: Predicate[Claim], /) -> Optional[Claim]:
        """
        Retrieves the first ``Claim``'s that match matches.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def find_first(self, claim_type: str, /) -> Optional[Claim]:
        """
        Retrieves the first ``Claim``'s where the ``Claim.type`` equals ``claim_type``.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    def find_first(self, _match) -> Optional[Claim]:
        if isfunction(_match):
            for claim in self.claims:
                if _match(claim):
                    return claim
            return None
        elif isinstance(_match, str):
            return self.find_first(lambda c: bool(c and c.type == _match))
        else:
            raise NotImplemented

    @overload
    def find_first_value(self, _match: Predicate[Claim], /) -> Optional[Any]:
        """
        Return the claim value for the first claim with the specified match if it exists, null otherwise.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def find_first_value(self, claim_type: str, /) -> Optional[Any]:
        """
        Return the claim value for the first claim with the specified ``claim_type`` if it exists, null otherwise.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    def find_first_value(self, _match) -> Optional[Any]:
        if isfunction(_match):
            if claim := self.find_first(_match):
                return claim.value
            return None
        elif isinstance(_match, str):
            return self.find_first_value(lambda c: bool(c and c.type == _match))
        else:
            raise NotImplemented

    @overload
    def has_claim(self, _match: Predicate[Claim], /) -> bool:
        """
        Determines if a claim is contained within all the ``ClaimsIdentities`` in this ``ClaimPrincipal``.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def has_claim(self, claim_type: str, claim_value: Any, /) -> bool:
        """
        Determines if a claim of ``claim_type`` AND ``claim_value`` exists in any of the identities.

        :param claim_type: The type of the claim to match.
        :param claim_value:  The value of the claim to match.
        :return:
        """
        ...

    def has_claim(self, *args) -> bool:
        _len = len(args)

        match _len:
            case 1:
                _match, = args
                if not isfunction(_match):
                    raise ValueError('_match must be Callable[[Claim], bool]')

                for claim in self.claims:
                    if _match(claim):
                        return True
                return False
            case 2:
                claim_type, claim_value = args
                if isinstance(claim_type, str):
                    return self.has_claim(lambda c: bool(c and c.type == claim_type and c.value == claim_value))

                raise TypeError('claim_type must be "str"')
            case _:
                raise NotImplemented

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} auth:{self.authentication_type} at {id(self)}>'


class ClaimsPrincipal:
    __slots__ = ('_identities',)

    def __init__(self, *identities: ClaimsIdentity) -> None:
        self._identities: list[ClaimsIdentity] = list(identities) if identities else []

    @property
    def identities(self) -> tuple[ClaimsIdentity, ...]:
        return tuple(self._identities)

    @property
    def identity(self) -> ClaimsIdentity:
        return self.select_primary_identity(self._identities)

    @property
    def claims(self) -> Generator[Claim]:
        for identity in self._identities:
            for claim in identity.claims:
                yield claim

    @overload
    def find_all(self, _match: Predicate[Claim], /) -> Generator[Claim]:
        """
        Retrieves a ``Claim``'s where match matches each claim.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def find_all(self, claim_type: str, /) -> Generator[Claim]:
        """
        Retrieves a ``Claim``'s where each ``Claim.type`` equals claim_type.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    def find_all(self, _match) -> Generator[Claim]:
        if isfunction(_match):
            for identity in self._identities:
                for claim in identity.find_all(_match):
                    yield claim
        elif isinstance(_match, str):
            yield from self.find_all(lambda c: bool(c and c.type == _match))
        else:
            raise NotImplemented

    @overload
    def find_first(self, _match: Predicate[Claim], /) -> Optional[Claim]:
        """
        Retrieves the first ``Claim``'s that match matches.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def find_first(self, claim_type: str, /) -> Optional[Claim]:
        """
        Retrieves the first ``Claim``'s where the ``Claim.type`` equals ``claim_type``.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    def find_first(self, _match):
        if isfunction(_match):
            for identity in self._identities:
                if claim := identity.find_first(_match):
                    return claim
            return None
        elif isinstance(_match, str):
            return self.find_first(lambda c: bool(c and c.type == _match))
        else:
            raise NotImplemented

    @overload
    def find_first_value(self, _match: Predicate[Claim], /) -> Optional[str]:
        """
        Return the claim value for the first claim with the specified match if it exists, null otherwise.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def find_first_value(self, claim_type: str, /) -> Optional[str]:
        """
        Return the claim value for the first claim with the specified ``claim_type`` if it exists, null otherwise.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    def find_first_value(self, _match) -> Optional[str]:
        if isfunction(_match):
            if claim := self.find_first(_match):
                return claim.value
            return None
        elif isinstance(_match, str):
            return self.find_first_value(lambda c: bool(c and c.type == _match))
        else:
            raise NotImplemented

    @overload
    def has_claim(self, _match: Predicate[Claim], /) -> bool:
        """
        Determines if a claim is contained within all the ``ClaimsIdentities`` in this ``ClaimPrincipal``.

        :param _match: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def has_claim(self, claim_type: str, claim_value: Any, /) -> bool:
        """
        Determines if a claim of ``claim_type`` AND ``claim_value`` exists in any of the identities.

        :param claim_type: The type of the claim to match.
        :param claim_value:  The value of the claim to match.
        :return:
        """
        ...

    def has_claim(self, *args) -> bool:
        _len = len(args)

        match _len:
            case 1:
                _match, = args
                if not isfunction(_match):
                    raise ValueError('_match must be Callable[[Claim], bool]')

                for identity in self._identities:
                    if identity.has_claim(_match):
                        return True
                return False
            case 2:
                claim_type, claim_value = args
                if isinstance(claim_type, str):
                    return self.has_claim(lambda c: bool(c and c.type == claim_type and c.value == claim_value))

                raise TypeError('claim_type must be "str"')
            case _:
                raise NotImplemented

    def select_primary_identity(self, identities: Iterable[ClaimsIdentity]) -> ClaimsIdentity:
        if not identities:
            raise ArgumentNoneException('identities')

        for identity in identities:
            if identity.authentication_type:
                return identity

    def add_identities(self, *identities: ClaimsIdentity) -> None:
        """
        Adds ``ClaimsIdentity`` to the internal list.

        :param identities:
        :return:
        """
        if not identities:
            raise ArgumentNoneException('identities')

        self._identities.extend(identities)

    def is_in_role(self, role: str) -> bool:
        """
        ``is_in_role`` answers the question: does an builders this principal possesses
        contains a claim of type ``role_claim_type`` where the value is '==' to the role.

        :param role: The role to check for.
        :return:
        """
        for _identity in self._identities:
            if _identity.has_claim(_identity.role_claim_type, role):
                return True
        return False

    def is_in_roles(self, *roles: str, mode: Literal['all', 'any'] = 'all') -> bool:
        """
        ``is_in_role`` answers the question: does an builders this principal possesses
        contains a claim of type ``role_claim_type`` where the value is '==' to the roles.

        :param roles: The roles to check for.
        :param mode: Verification mode.
        :return:
        """
        if not roles:
            raise ArgumentNoneException('roles')

        match mode:
            case 'all':
                return all(False for role in roles if not self.is_in_role(role))
            case 'any':
                return any(True for role in roles if self.is_in_role(role))
            case _:
                raise ValueError('the "mode" must be "all" or "any"')
