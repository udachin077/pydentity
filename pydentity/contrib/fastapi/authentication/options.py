from collections.abc import Callable
from inspect import isfunction
from typing import overload

from pydentity.contrib.fastapi.authentication.scheme import AuthenticationScheme, AuthenticationSchemeBuilder
from pydentity.exc import InvalidOperationException, ArgumentNoneException


class AuthenticationOptions:
    __slots__ = (
        '_scheme_map',
        'default_scheme',
        'default_sign_in_scheme',
        'default_sign_out_scheme',
        'required_authenticated_signin'
    )

    def __init__(self):
        self._scheme_map = {}
        self.default_scheme: str = None
        self.default_sign_in_scheme: str = None
        self.default_sign_out_scheme: str = None
        self.required_authenticated_signin: bool = True

    @overload
    def add_scheme(self, name: str, scheme: AuthenticationScheme) -> None:
        pass

    @overload
    def add_scheme(self, name: str, configure_scheme: Callable[[AuthenticationSchemeBuilder], None]) -> None:
        pass

    def add_scheme(
            self,
            name: str,
            scheme_or_builder: AuthenticationScheme | Callable[[AuthenticationSchemeBuilder], None]
    ) -> None:
        if not name:
            raise ArgumentNoneException('name')
        if not scheme_or_builder:
            raise ArgumentNoneException('scheme_or_builder')

        if name in self._scheme_map:
            raise InvalidOperationException(f'Scheme already exists: {name}.')

        if isinstance(scheme_or_builder, AuthenticationScheme):
            self._scheme_map[name] = scheme_or_builder

        elif isfunction(scheme_or_builder):
            builder = AuthenticationSchemeBuilder(name)
            scheme_or_builder(builder)
            self._scheme_map[name] = builder.build()

        else:
            raise NotImplemented

