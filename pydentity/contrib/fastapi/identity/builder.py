from collections.abc import Iterable

from pydentity.contrib.fastapi.depends import dep, def_dep
from pydentity import (
    IdentityErrorDescriber,
    EmailTokenProvider,
    PhoneNumberTokenProvider,
    AuthenticatorTokenProvider,
    DataProtectorTokenProvider
)
from pydentity.abc import (
    IUserValidator,
    IUserClaimsPrincipalFactory,
    IPasswordValidator,
    IRoleValidator,
    IUserConfirmation,
    IUserTwoFactorTokenProvider, IPersonalDataProtector
)
from pydentity.abc.stores import IUserStore, IRoleStore
from pydentity.contrib.fastapi.core.abc import IServiceCollection
from pydentity.contrib.fastapi.types import DependencyCallable
from pydentity.identity_options import TokenOptions
from pydentity.types import TUser, TRole


class IdentityBuilder:
    def __init__(self, user: type[TUser], role: type[TRole], services: IServiceCollection):
        self.user = user
        self.role = role
        self.__services = services

    def add_user_validator(self, validator: type[IUserValidator[TUser]]):
        self.__services.add_service(
            dep.IUserValidatorCollection,
            def_dep.get_uv.get_instance(validator)
        )
        return self

    def replace_user_validators(self, func: DependencyCallable[Iterable[IUserValidator[TUser]]]):
        self.__services.add_service(dep.IUserValidatorCollection, func)
        return self

    def add_user_claims_principal_factory(self, func: DependencyCallable[IUserClaimsPrincipalFactory[TUser]]):
        self.__services.add_service(dep.IUserClaimsPrincipalFactory, func)
        return self

    def add_identity_error_describer(self, func: DependencyCallable[IdentityErrorDescriber]):
        self.__services.add_service(dep.IdentityErrorDescriber, func)
        return self

    def add_password_validator(self, validator: type[IPasswordValidator[TUser]]):
        self.__services.add_service(
            dep.IPasswordValidatorCollection,
            def_dep.get_pv.get_instance(validator)
        )
        return self

    def replace_password_validators(self, func: DependencyCallable[Iterable[IPasswordValidator[TUser]]]):
        self.__services.add_service(dep.IPasswordValidatorCollection, func)
        return self

    def add_user_store(self, func: DependencyCallable[IUserStore[TUser]]):
        self.__services.add_service(dep.IUserStore, func)
        return self

    def add_user_manager[TUserManager](self, func: DependencyCallable[TUserManager]):
        self.__services.add_service(dep.UserManager, func)
        return self

    def add_role_validator(self, validator: type[IRoleValidator[TRole]]):
        self.__services.add_service(
            dep.IRoleValidatorCollection,
            def_dep.get_rv.get_instance(validator)
        )
        return self

    def replace_role_validators(self, func: DependencyCallable[Iterable[IRoleValidator[TRole]]]):
        self.__services.add_service(dep.IRoleValidatorCollection, func)
        return self

    def add_role_store(self, func: DependencyCallable[IRoleStore[TRole]]):
        self.__services.add_service(dep.IRoleStore, func)
        return self

    def add_role_manager[TRoleManager](self, func: DependencyCallable[TRoleManager]):
        self.__services.add_service(dep.RoleManager, func)
        return self

    def add_user_confirmation(self, func: DependencyCallable[IUserConfirmation[TUser]]):
        self.__services.add_service(dep.IUserConfirmation, func)
        return self

    def add_token_provider(self, provider_name: str, provider: IUserTwoFactorTokenProvider[TUser]):
        self.__services.get(dep.IdentityOptions)().Tokens.PROVIDER_MAP[provider_name] = provider
        return self

    def add_default_token_providers(self):
        self.add_token_provider(TokenOptions.DEFAULT_PROVIDER, DataProtectorTokenProvider())
        self.add_token_provider(TokenOptions.DEFAULT_EMAIL_PROVIDER, EmailTokenProvider())
        self.add_token_provider(TokenOptions.DEFAULT_PHONE_PROVIDER, PhoneNumberTokenProvider())
        self.add_token_provider(TokenOptions.DEFAULT_AUTHENTICATION_PROVIDER, AuthenticatorTokenProvider())
        return self

    def add_personal_data_protection(self, func: DependencyCallable[IPersonalDataProtector]):
        self.__services.add_service(dep.IPersonalDataProtectorDepends, func)
        return self

    def add_signin_manager[TSignInManager](self, func: DependencyCallable[TSignInManager]):
        self.__services.add_service(dep.SignInManager, func)
        return self
