import string
from datetime import timedelta

from pydentity.abc import IUserTwoFactorTokenProvider
from pydentity.security.claims import ClaimTypes
from pydentity.types import TUser


class LockoutOptions:
    """Options for configuring user lockout."""

    __slots__ = (
        'allowed_for_new_user',
        'default_lockout_timespan',
        'max_failed_access_attempts',
    )

    def __init__(self) -> None:
        self.allowed_for_new_user: bool = True
        """Gets or sets a flag indicating whether a new user can be locked out. Defaults to `True`."""
        self.default_lockout_timespan: timedelta = timedelta(minutes=5)
        """Gets or sets the :exc:`timedelta` a user is locked out for when a lockout occurs. Defaults to `5` minutes."""
        self.max_failed_access_attempts: int = 5
        """Gets or sets the number of failed access attempts allowed before a user is locked out, 
        assuming lock out is enabled. Defaults to `5`."""


class ClaimsIdentityOptions:
    """Options used to configure the claim types used for well known claims."""

    __slots__ = (
        'role_claim_type',
        'username_claim_type',
        'user_id_claim_type',
        'email_claim_type',
        'security_stamp_claim_type',
    )

    def __init__(self) -> None:
        self.role_claim_type = ClaimTypes.Role
        """Gets or sets the :exc:`ClaimTypes` used for a Role claim. 
        Defaults to :exc:`ClaimTypes.Role`."""
        self.username_claim_type = ClaimTypes.Name
        """Gets or sets the :exc:`ClaimTypes` used for the user name claim. 
        Defaults to :exc:`ClaimTypes.Name`."""
        self.user_id_claim_type = ClaimTypes.NameIdentifier
        """Gets or sets the :exc:`ClaimTypes` used for the user identifier claim. 
        Defaults to :exc:`ClaimTypes.NameIdentifier`."""
        self.email_claim_type = ClaimTypes.Email
        """Gets or sets the :exc:`ClaimTypes` used for the user email claim. 
        Defaults to :exc:`ClaimTypes.Email`."""
        self.security_stamp_claim_type = ClaimTypes.SecurityStamp
        """Gets or sets the :exc:`ClaimTypes` used for the security stamp claim. 
        Defaults to `ClaimTypes.SecurityStamp`."""


class PasswordOptions:
    """Specifies options for password requirements."""

    __slots__ = (
        'require_digit',
        'required_length',
        'required_unique_chars',
        'required_lowercase',
        'required_non_alphanumeric',
        'required_uppercase',
    )

    def __init__(self) -> None:
        self.require_digit: bool = True
        """Gets or sets a flag indicating if passwords must contain a digit. Defaults to `True`."""
        self.required_length: int = 8
        """Gets or sets the minimum length a password must be. Defaults to `8`."""
        self.required_unique_chars: int = 1
        """Gets or sets the minimum number of unique characters which a password must contain. Defaults to `1`."""
        self.required_lowercase: bool = True
        """Gets or sets a flag indicating if passwords must contain a lower case ASCII character. Defaults to `True`."""
        self.required_non_alphanumeric: bool = True
        """Gets or sets a flag indicating if passwords must contain a non-alphanumeric character. Defaults to `True`."""
        self.required_uppercase: bool = True
        """Gets or sets a flag indicating if passwords must contain a upper case ASCII character. Defaults to `True`."""


class SignInOptions:
    """Options for configuring sign in."""

    __slots__ = (
        'required_confirmed_email',
        'required_confirmed_phone_number',
        'required_confirmed_account',
    )

    def __init__(self) -> None:
        self.required_confirmed_email: bool = False
        """Gets or sets a flag indicating whether a confirmed email address is required to sign in. 
        Defaults to `False`."""
        self.required_confirmed_phone_number: bool = False
        """Gets or sets a flag indicating whether a confirmed telephone number is required to sign in. 
        Defaults to `False`."""
        self.required_confirmed_account: bool = False
        """Gets or sets a flag indicating whether a confirmed :exc:`IUserConfirmation[TUser]` 
        account is required to sign in. Defaults to `False`."""


class TokenOptions:
    """Options for user tokens."""

    __slots__ = (
        'change_email_token_provider',
        'change_phone_number_token_provider',
        'email_confirmation_token_provider',
        'phone_number_confirmation_token_provider',
        'password_reset_token_provider',
        'authenticator_token_provider',
        'totp_interval',
        'provider_map',
    )

    def __init__(self) -> None:
        self.authenticator_token_provider: str = "Authenticator"
        """Gets or sets the token provider used to validate two factor sign ins with an authenticator."""
        self.change_email_token_provider: str = "Email"
        """Gets or sets the token provider used to generate tokens used in email change confirmation emails."""
        self.change_phone_number_token_provider: str = "Phone"
        """Gets or sets the token provider used to generate tokens used when changing phone numbers."""
        self.email_confirmation_token_provider: str = "Email"
        """Gets or sets the token provider used to generate tokens used in account confirmation emails."""
        self.phone_number_confirmation_token_provider: str = "Phone"
        """Gets or sets the token provider used to generate tokens used in account confirmation phone number."""
        self.password_reset_token_provider: str = "Default"
        """Gets or sets the token provider used to generate tokens used in password reset emails."""
        self.totp_interval = 30
        """Gets or sets the totp interval. Defaults to `30` seconds."""
        self.provider_map: dict[str, IUserTwoFactorTokenProvider[TUser]] = {}  # type: ignore


class UserOptions:
    """Options for user validation."""

    __slots__ = (
        'allowed_username_characters',
        'require_unique_email',
        'allowed_email_domains',
    )

    def __init__(self) -> None:
        self.allowed_username_characters: str = ''.join([string.ascii_letters, string.digits, '@-_.'])
        """Gets or sets the list of allowed characters in the username used to validate user names. 
        Defaults to `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-_`"""
        self.require_unique_email: bool = True
        """Gets or sets a flag indicating whether the application requires unique emails for its auth. 
        Defaults to `True`."""
        self.allowed_email_domains: list[str] = []
        """Gets or sets a list of available domains for email. Defaults to [].
        If the list is empty then any domains are available."""


class StoreOptions:
    """Used for store specific options."""

    __slots__ = ('protect_personal_data',)

    def __init__(self) -> None:
        self.protect_personal_data: bool = False
        """If set to True, the store must protect all personally identifying data for a user. 
        This will be enforced by requiring the store to implement :exc:`IProtectedUserStore[TUser]`."""


class IdentityOptions:
    """Represents all the options you can use to configure the identity system."""

    __slots__ = (
        'claims_identity',
        'lockout',
        'password',
        'signin',
        'tokens',
        'user',
    )

    def __init__(self) -> None:
        self.claims_identity: ClaimsIdentityOptions = ClaimsIdentityOptions()
        """Gets or sets the :exc:`ClaimsIdentityOptions` for the identity system."""
        self.lockout: LockoutOptions = LockoutOptions()
        """Gets or sets the :exc:`LockoutOptions` for the identity system."""
        self.password: PasswordOptions = PasswordOptions()
        """Gets or sets the :exc:`PasswordOptions` for the identity system."""
        self.signin: SignInOptions = SignInOptions()
        """Gets or sets the :exc:`SignInOptions` for the identity system."""
        self.tokens: TokenOptions = TokenOptions()
        """Gets or sets the :exc:`TokenOptions` for the identity system."""
        self.user: UserOptions = UserOptions()
        """Gets or sets the :exc:`UserOptions` for the identity system."""
