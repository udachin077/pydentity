from collections.abc import Iterator
from typing import Iterable, Annotated

from fastapi import Depends

from pydentity import IdentityErrorDescriber
from pydentity.abc import (
    IPasswordValidator,
    IRoleValidator,
    IUserValidator,
)


class Singleton:
    def __init__(self, cls):
        self.__wrapped__ = cls
        self._instance = None

    def __call__(self, *args, **kwargs):
        if self._instance is None:
            self._instance = self.__wrapped__(*args, **kwargs)
        return self._instance


def singleton(cls):
    return Singleton(cls)


class ValidatorCollection(Iterable[IUserValidator | IRoleValidator | IPasswordValidator]):
    __slots__ = ("errors", "validators",)

    def __init__(self, errors: Annotated[IdentityErrorDescriber, Depends()]) -> None:
        self.errors = errors

    def __iter__(self) -> Iterator[IUserValidator | IRoleValidator | IPasswordValidator]:
        for item in self.validators:
            yield item(self.errors)


class PasswordValidatorCollection(ValidatorCollection[IPasswordValidator]):
    validators: set[type[IPasswordValidator]] = set()


class UserValidatorCollection(ValidatorCollection[IUserValidator]):
    validators: set[type[IUserValidator]] = set()


class RoleValidatorCollection(ValidatorCollection[IRoleValidator]):
    validators: set[type[IRoleValidator]] = set()


class Dependencies(dict[type, type]):
    def __init__(self):
        super().__init__()
