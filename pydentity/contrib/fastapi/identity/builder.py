from abc import abstractmethod
from collections.abc import Iterable

from fastapi import Depends

from pydentity import (
    IdentityOptions,
    UpperLookupNormalizer,
    DefaultUserConfirmation,
    Argon2PasswordHasher,
    DataProtectorTokenProvider,
    EmailTokenProvider,
    PhoneNumberTokenProvider,
    AuthenticatorTokenProvider,
    SignInManager,
    UserValidator,
    PasswordValidator,
    RoleValidator,
    UserManager,
    RoleManager,
    UserClaimsPrincipalFactory,
    IdentityErrorDescriber
)
from pydentity.abc import (
    IPasswordHasher,
    ILookupNormalizer,
    IUserConfirmation,
    IUserClaimsPrincipalFactory,
    IUserValidator,
    IPasswordValidator,
    IRoleValidator,
    IUserTwoFactorTokenProvider, IPersonalDataProtector
)
from pydentity.abc.stores import IUserStore, IRoleStore
from pydentity.identity_options import TokenOptions
from pydentity.types import TUser, TRole


class _ProxyValidators(Iterable):
    __slots__ = ('errors', 'validators',)

    def __init__(self, errors: IdentityErrorDescriber = Depends()):
        self.errors = errors

    def __iter__(self):
        for item in self.validators:
            yield item(self.errors)


class _PasswordValidators(_ProxyValidators):
    validators: set[type[IPasswordValidator]] = set()


class _UserValidators(_ProxyValidators):
    validators: set[type[IUserValidator]] = set()


class _RoleValidators(_ProxyValidators):
    validators: set[type[IRoleValidator]] = set()


class IdentityBuilder:
    def __init__(self, user_store: type[IUserStore], role_store: type[IRoleStore]) -> None:
        self._services_map = {}
        self._token_provider_map = {}
        self._add_default_identity(user_store, role_store)

    def add_user_validator(self, validator: type[IUserValidator[TUser]]) -> 'IdentityBuilder':
        _UserValidators.validators.update((validator,))
        return self

    def add_user_claims_principal_factory(self, factory: type[IUserClaimsPrincipalFactory[TUser]]) -> 'IdentityBuilder':
        self._setitem(IUserClaimsPrincipalFactory, factory)
        return self

    def add_identity_error_describer(self, describer: type[IdentityErrorDescriber]) -> 'IdentityBuilder':
        self._setitem(IdentityErrorDescriber, describer)
        return self

    def add_password_validator(self, validator: type[IPasswordValidator[TUser]]) -> 'IdentityBuilder':
        _PasswordValidators.validators.update((validator,))
        return self

    def add_user_store(self, store: type[IUserStore[TUser]]) -> 'IdentityBuilder':
        self._setitem(IUserStore, store)
        return self

    def add_user_manager(self, manager: type[UserManager]) -> 'IdentityBuilder':
        self._setitem(UserManager, manager)
        return self

    def add_role_validator(self, validator: type[IRoleValidator[TRole]]) -> 'IdentityBuilder':
        _RoleValidators.validators.update((validator,))
        return self

    def add_role_store(self, store: type[IRoleStore[TRole]]) -> 'IdentityBuilder':
        self._setitem(IRoleStore, store)
        return self

    def add_role_manager(self, manager: type[RoleManager]) -> 'IdentityBuilder':
        self._setitem(RoleManager, manager)
        return self

    def add_user_confirmation(self, user_confirmation: type[IUserConfirmation[TUser]]) -> 'IdentityBuilder':
        self._setitem(IUserConfirmation, user_confirmation)
        return self

    def add_token_provider(self, provider_name: str, provider: IUserTwoFactorTokenProvider[TUser]) -> 'IdentityBuilder':
        self._token_provider_map[provider_name] = provider
        return self

    def add_signin_manager(self, manager: type[SignInManager]) -> 'IdentityBuilder':
        self._setitem(SignInManager, manager)
        return self

    @abstractmethod
    def add_personal_data_protection(self, protector: IPersonalDataProtector) -> 'IdentityBuilder':
        pass

    def add_default_token_providers(self) -> 'IdentityBuilder':
        self.add_token_provider(TokenOptions.DEFAULT_PROVIDER, DataProtectorTokenProvider())
        self.add_token_provider(TokenOptions.DEFAULT_EMAIL_PROVIDER, EmailTokenProvider())
        self.add_token_provider(TokenOptions.DEFAULT_PHONE_PROVIDER, PhoneNumberTokenProvider())
        self.add_token_provider(TokenOptions.DEFAULT_AUTHENTICATION_PROVIDER, AuthenticatorTokenProvider())
        return self

    def bind_app(self, app) -> None:
        for val in self._services_map.values():
            func = getattr(app.services, val.pop('func'))
            func(**val)

        options = app.services.resolve(IdentityOptions)
        options.tokens.provider_map.update(self._token_provider_map)

    def _setitem(self, key, value) -> None:
        self._services_map[key]['concrete_type'] = value

    def _add_default_identity(self, user_store, role_store) -> None:
        _UserValidators.validators.update((UserValidator,))
        _PasswordValidators.validators.update((PasswordValidator,))
        _RoleValidators.validators.update((RoleValidator,))

        self._services_map.update({
            IdentityOptions: {
                'func': 'add_singleton',
                'base_type': IdentityOptions,
                'concrete_type': IdentityOptions
            },
            IUserStore: {
                'func': 'add_scoped',
                'base_type': IUserStore,
                'concrete_type': user_store
            },
            IRoleStore: {
                'func': 'add_scoped',
                'base_type': IRoleStore,
                'concrete_type': role_store
            },
            IdentityErrorDescriber: {
                'func': 'add_scoped',
                'base_type': IdentityErrorDescriber,
                'concrete_type': IdentityErrorDescriber
            },
            IPasswordHasher: {
                'func': 'add_scoped',
                'base_type': IPasswordHasher,
                'concrete_type': Argon2PasswordHasher
            },
            ILookupNormalizer: {
                'func': 'add_scoped',
                'base_type': ILookupNormalizer,
                'concrete_type': UpperLookupNormalizer
            },
            IUserConfirmation: {
                'func': 'add_scoped',
                'base_type': IUserConfirmation,
                'concrete_type': DefaultUserConfirmation
            },
            IUserClaimsPrincipalFactory: {
                'func': 'add_scoped',
                'base_type': IUserClaimsPrincipalFactory,
                'concrete_type': UserClaimsPrincipalFactory
            },
            _UserValidators: {
                'func': 'add_scoped',
                'base_type': _UserValidators,
                'concrete_type': _UserValidators
            },
            _PasswordValidators: {
                'func': 'add_scoped',
                'base_type': _PasswordValidators,
                'concrete_type': _PasswordValidators
            },
            _RoleValidators: {
                'func': 'add_scoped',
                'base_type': _RoleValidators,
                'concrete_type': _RoleValidators
            },
            UserManager: {
                'func': 'add_scoped',
                'base_type': UserManager,
                'concrete_type': UserManager
            },
            RoleManager: {
                'func': 'add_scoped',
                'base_type': RoleManager,
                'concrete_type': RoleManager
            },
            # SignInManager: {
            #     'func': add_scoped,
            #     'base_type': SignInManager,
            #     'concrete_type': SignInManager
            # }
        })
