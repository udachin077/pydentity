from collections.abc import Iterable
from typing import Annotated

from fastapi import Depends

from pydentity import (
    IdentityErrorDescriber,
    UserManager,
    RoleManager,
    IdentityOptions,
    SignInManager,
    UserClaimsPrincipalFactory,
    Argon2PasswordHasher, UpperLookupNormalizer, DefaultUserConfirmation
)
from pydentity.abc import (
    IPasswordValidator,
    IPasswordHasher,
    ILookupNormalizer,
    IUserConfirmation,
    IUserClaimsPrincipalFactory,
    IUserValidator,
    IRoleValidator,
)
from pydentity.abc.stores import (
    IUserStore,
    IRoleStore
)
from pydentity.contrib.fastapi import HttpContext
from pydentity.contrib.fastapi.depends.base import *


def get_io():
    yield IdentityOptions()


def get_ied():
    yield IdentityErrorDescriber()


def get_ph():
    yield Argon2PasswordHasher()


def get_ln():
    yield UpperLookupNormalizer()


def get_uc():
    yield DefaultUserConfirmation()


class get_uv:
    validator_types: list[IUserValidator] = []

    @classmethod
    def get_instance(cls, *args) -> 'get_uv':
        cls.validator_types.extend(args)
        return super().__new__(cls)

    def __call__(
            self,
            describer: Annotated[IdentityErrorDescriber, Depends(IdentityErrorDescriber)]
    ) -> Iterable[IUserValidator]:
        return [vt(describer) for vt in self.validator_types]


class get_pv:
    validator_types: list[IPasswordValidator] = []

    @classmethod
    def get_instance(cls, *args) -> 'get_pv':
        cls.validator_types.extend(args)
        return super().__new__(cls)

    def __call__(
            self,
            describer: Annotated[IdentityErrorDescriber, Depends(IdentityErrorDescriber)]
    ) -> Iterable[IPasswordValidator]:
        return [vt(describer) for vt in self.validator_types]


class get_rv:
    validator_types: list[IRoleValidator] = []

    @classmethod
    def get_instance(cls, *args) -> 'get_rv':
        cls.validator_types.extend(args)
        return super().__new__(cls)

    def __call__(
            self,
            describer: Annotated[IdentityErrorDescriber, Depends(IRoleValidator)]
    ) -> Iterable[IPasswordValidator]:
        return [vt(describer) for vt in self.validator_types]


def get_user_manager(
        store: Annotated[IUserStore, Depends(IUserStore)],
        options: Annotated[IdentityOptions, Depends(IdentityOptions)],
        password_hasher: Annotated[IPasswordHasher, Depends(IPasswordHasher)],
        password_validators: Annotated[Iterable[IPasswordValidator], Depends(IPasswordValidatorCollection)],
        user_validators: Annotated[Iterable[IUserValidator], Depends(IUserValidatorCollection)],
        key_normalizer: Annotated[ILookupNormalizer, Depends(ILookupNormalizer)],
        describer: Annotated[IdentityErrorDescriber, Depends(IdentityErrorDescriber)]
):
    yield UserManager(
        store,
        options=options,
        password_hasher=password_hasher,
        password_validators=password_validators,
        user_validators=user_validators,
        key_normalizer=key_normalizer,
        errors=describer
    )


def get_role_manager(
        store: Annotated[IRoleStore, Depends(IRoleStore)],
        role_validators: Annotated[Iterable[IRoleValidator], Depends(IRoleValidatorCollection)],
        key_normalizer: Annotated[ILookupNormalizer, Depends(ILookupNormalizer)],
        describer: Annotated[IdentityErrorDescriber, Depends(IdentityErrorDescriber)]
):
    yield RoleManager(
        store,
        role_validators=role_validators,
        key_normalizer=key_normalizer,
        errors=describer
    )


def get_ucpf(
        user_manager: Annotated[UserManager, Depends(UserManager)],
        role_manager: Annotated[RoleManager, Depends(RoleManager)],
        options: Annotated[IdentityOptions, Depends(IdentityOptions)],
):
    yield UserClaimsPrincipalFactory(
        user_manager,
        role_manager,
        options
    )


def get_signin_manager(
        context: Annotated[HttpContext, Depends(HttpContext)],
        user_manager: Annotated[UserManager, Depends(UserManager)],
        claims_factory: Annotated[IUserClaimsPrincipalFactory, Depends(IUserClaimsPrincipalFactory)],
        confirmation: Annotated[IUserConfirmation, Depends(IUserConfirmation)],
        options: Annotated[IdentityOptions, Depends(IdentityOptions)],
):
    yield SignInManager(
        user_manager,
        context=context,
        schemes=None,
        claims_factory=claims_factory,
        confirmation=confirmation,
        options=options
    )
