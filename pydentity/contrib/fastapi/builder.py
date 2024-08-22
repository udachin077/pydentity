from collections.abc import Iterable, Callable

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.types import ExceptionHandler

from pydentity import (
    IdentityOptions,
    UserManager,
    RoleManager,
    SignInManager,
    IdentityErrorDescriber,
    UserValidator,
    PasswordValidator,
    RoleValidator
)
from pydentity.abc import (
    IPasswordHasher,
    ILookupNormalizer,
    IUserConfirmation,
    IUserClaimsPrincipalFactory, IUserValidator, IPasswordValidator, IRoleValidator
)
from pydentity.abc.stores import IUserStore, IRoleStore
from pydentity.contrib.fastapi.authentication import AuthenticationBuilder
from pydentity.contrib.fastapi.authentication.exc import AuthenticationError
from pydentity.contrib.fastapi.authentication.options import AuthenticationOptions
from pydentity.contrib.fastapi.authentication.provider import AuthenticationSchemeProvider
from pydentity.contrib.fastapi.authorization import AuthorizationBuilder
from pydentity.contrib.fastapi.authorization.exc import AuthorizationError
from pydentity.contrib.fastapi.authorization.options import AuthorizationOptions
from pydentity.contrib.fastapi.authorization.provider import AuthorizationProvider
from pydentity.contrib.fastapi.core.abc import IServiceCollection
from pydentity.contrib.fastapi.core.collection import ServiceCollection
from pydentity.contrib.fastapi.depends import dep, def_dep
from pydentity.contrib.fastapi.identity.builder import IdentityBuilder
from pydentity.contrib.fastapi.types import DependencyCallable
from pydentity.exc import ArgumentNoneException
from pydentity.identity_constants import IdentityConstants
from pydentity.types import TUser, TRole

__all__ = ('PydentityBuilder',)


def configure_authenticate(o: AuthenticationOptions):
    o.default_scheme = IdentityConstants.ApplicationScheme
    o.default_sign_in_scheme = IdentityConstants.ExternalScheme


class PydentityBuilder:
    def __init__(self, app: FastAPI):
        self.app = app
        self.services: IServiceCollection = ServiceCollection()

    def _add_identity_core(
            self,
            get_user_store: DependencyCallable[IUserStore[TUser]],
            get_role_store: DependencyCallable[IRoleStore[TRole]]
    ):
        self.services.add_service(dep.IdentityOptions, def_dep.get_io)
        self.services.add_service(dep.IUserStore, get_user_store)
        self.services.add_service(dep.IRoleStore, get_role_store)

        self.services.add_service(dep.IPasswordHasher, def_dep.get_ph)
        self.services.add_service(dep.ILookupNormalizer, def_dep.get_ln)
        self.services.add_service(dep.IdentityErrorDescriber, def_dep.get_ied)
        self.services.add_service(dep.IUserConfirmation, def_dep.get_uc)
        self.services.add_service(dep.IUserClaimsPrincipalFactory, def_dep.get_ucpf)
        self.services.add_service(dep.IUserValidatorCollection, def_dep.get_uv.get_instance(UserValidator))
        self.services.add_service(dep.IPasswordValidatorCollection, def_dep.get_pv.get_instance(PasswordValidator))
        self.services.add_service(dep.IRoleValidatorCollection, def_dep.get_rv.get_instance(RoleValidator))

        self.services.add_service(dep.UserManager, def_dep.get_user_manager)
        self.services.add_service(dep.RoleManager, def_dep.get_role_manager)
        self.services.add_service(dep.SignInManager, def_dep.get_signin_manager)

    def add_default_identity(
            self,
            user: type[TUser],
            role: type[TRole],
            get_user_store: DependencyCallable[IUserStore[TUser]],
            get_role_store: DependencyCallable[IRoleStore[TRole]],
            configure: Callable[[IdentityOptions], None] | None = None
    ):
        if not get_user_store:
            raise ArgumentNoneException('get_user_store')
        if not get_role_store:
            raise ArgumentNoneException('get_role_store')

        self._add_identity_core(get_user_store, get_role_store)

        self.add_authentication(configure_authenticate).add_identity_cookies()

        _options = IdentityOptions()
        if configure:
            configure(_options)

        self.services.add_service(IdentityOptions, dep.IdentityOptions)
        self.services.add_service(IUserStore, dep.IUserStore)
        self.services.add_service(IRoleStore, dep.IRoleStore)

        self.services.add_service(IPasswordHasher, dep.IPasswordHasher)
        self.services.add_service(ILookupNormalizer, dep.ILookupNormalizer)
        self.services.add_service(IdentityErrorDescriber, dep.IdentityErrorDescriber)
        self.services.add_service(IUserConfirmation, dep.IUserConfirmation)
        self.services.add_service(IUserClaimsPrincipalFactory, dep.IUserClaimsPrincipalFactory)
        self.services.add_service(Iterable[IUserValidator], dep.IUserValidatorCollection)
        self.services.add_service(Iterable[IPasswordValidator], dep.IPasswordValidatorCollection)
        self.services.add_service(Iterable[IRoleValidator], dep.IRoleValidatorCollection)

        self.services.add_service(UserManager, dep.UserManager)
        self.services.add_service(RoleManager, dep.RoleManager)
        self.services.add_service(SignInManager, dep.SignInManager)
        return IdentityBuilder(user, role, self.services).add_default_token_providers()

    def add_authentication(
            self,
            configure: Callable[[AuthenticationOptions], None] | None = None,
            on_error: ExceptionHandler | None = None
    ):
        _options = AuthenticationOptions()
        if configure:
            configure(_options)

        if on_error:
            self.app.add_exception_handler(AuthorizationError, on_error)
        else:
            self.app.add_exception_handler(
                AuthenticationError,
                lambda req, exc: PlainTextResponse('Unauthorized', status_code=401)
            )

        AuthenticationSchemeProvider.options = _options
        return AuthenticationBuilder(_options)

    def add_authorization(
            self,
            configure: Callable[[AuthorizationOptions], None] | None = None,
            on_error: ExceptionHandler | None = None
    ):
        _options = AuthorizationOptions()
        if configure:
            configure(_options)

        if on_error:
            self.app.add_exception_handler(AuthorizationError, on_error)
        else:
            self.app.add_exception_handler(
                AuthorizationError,
                lambda req, exc: PlainTextResponse('Access denied', status_code=403)
            )

        AuthorizationProvider.options = _options
        return AuthorizationBuilder(_options)

    def add_identity_cookies(self):
        pass

    def build(self):
        self.app.dependency_overrides.update(self.services)
