import string
from datetime import timedelta


class LockoutOptions:
    """Options for configuring user lockout."""

    def __init__(self):
        self.ALLOWED_FOR_NEW_USER: bool = True
        """Gets or sets a flag indicating whether a new user can be locked out. 
        Defaults to True."""
        self.DEFAULT_LOCKOUT_TIMESPAN: timedelta = timedelta(minutes=5)
        """Gets or sets the timedelta a user is locked out for when a lockout occurs. 
        Defaults to 5 minutes."""
        self.MAX_FAILED_ACCESS_ATTEMPTS: int = 5
        """Gets or sets the number of failed access attempts allowed before a user is locked out, assuming 
        lock out is enabled. Defaults to 5."""


class PasswordOptions:
    """Specifies options for password requirements."""

    def __init__(self):
        self.REQUIRE_DIGIT: bool = True
        """Gets or sets a flag indicating if passwords must contain a digit. 
        Defaults to True."""
        self.REQUIRED_LENGTH: int = 8
        """Gets or sets the minimum length a password must be. 
        Defaults to 8."""
        self.REQUIRED_UNIQUE_CHARS: int = 1
        """Gets or sets the minimum number of unique characters which a password must contain. 
        Defaults to 1."""
        self.REQUIRE_LOWERCASE: bool = True
        """Gets or sets a flag indicating if passwords must contain a lower case ASCII character. 
        Defaults to True."""
        self.REQUIRE_NON_ALPHANUMERIC: bool = True
        """Gets or sets a flag indicating if passwords must contain a non-alphanumeric character. 
        Defaults to True."""
        self.REQUIRE_UPPERCASE: bool = True
        """Gets or sets a flag indicating if passwords must contain a upper case ASCII character. 
        Defaults to True."""


class SignInOptions:
    """Options for configuring sign in."""

    def __init__(self):
        self.REQUIRE_CONFIRMED_EMAIL: bool = False
        """Gets or sets a flag indicating whether a confirmed email address is required to sign in. 
        Defaults to False."""
        self.REQUIRED_CONFIRMED_PHONE_NUMBER: bool = False
        """Gets or sets a flag indicating whether a confirmed telephone number is required to sign in. 
        Defaults to False."""
        self.REQUIRE_CONFIRMED_ACCOUNT: bool = False


class TokenOptions:
    """Options for user tokens."""
    DEFAULT_PROVIDER: str = "Default"
    """Default token provider name used by email confirmation, password reset, and change email."""
    DEFAULT_EMAIL_PROVIDER: str = "Email"
    """Default token provider name used by the email provider."""
    DEFAULT_PHONE_PROVIDER: str = "Phone"
    """Default token provider name used by the phone provider."""
    CHANGE_EMAIL_TOKEN_PROVIDER: str = DEFAULT_EMAIL_PROVIDER
    """Gets or sets the change_email_token_provider used to generate tokens used in email change 
    confirmation emails."""
    CHANGE_PHONE_NUMBER_TOKEN_PROVIDER: str = DEFAULT_PHONE_PROVIDER
    """Gets or sets the change_phone_number_token_provider used to generate tokens used when changing 
    phone numbers."""
    EMAIL_CONFIRMATION_TOKEN_PROVIDER: str = DEFAULT_EMAIL_PROVIDER
    """Gets or sets the token provider used to generate tokens used in account confirmation emails"""
    PHONE_NUMBER_CONFIRMATION_TOKEN_PROVIDER: str = DEFAULT_PHONE_PROVIDER
    """Gets or sets the token provider used to generate tokens used in account confirmation phone_number"""
    PASSWORD_RESET_TOKEN_PROVIDER: str = DEFAULT_PROVIDER
    """Gets or sets the password_reset_token_provider used to generate tokens used in password reset emails."""
    TOTP_INTERVAL = 60
    """Gets or sets the totp interval. Defaults to 60 seconds."""

    def __init__(self):
        self.PROVIDER_MAP: dict[str, ...] = {}


class UserOptions:
    """Options for user validation."""

    ALLOWED_USERNAME_CHARACTERS: str = ''.join([string.ascii_letters, string.digits, '@-_.'])
    """Gets or sets the list of allowed characters in the username used to validate user names. 
    Defaults to abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-_"""
    REQUIRE_UNIQUE_EMAIL: bool = True
    """Gets or sets a flag indicating whether the application requires unique emails for its auth. 
    Defaults to True."""
    ALLOWED_EMAIL_DOMAINS: list[str] = []
    """Gets or sets a list of available domains for email. Defaults to [].
    If the list is empty then any domains are available."""


class StoreOptions:
    def __init__(self):
        self.PROTECT_PERSONAL_DATA: bool = False


class IdentityOptions:
    """Represents all the options you can use to configure the identity system."""

    def __init__(self):
        """Gets or sets the ClaimsIdentityOptions for the identity system."""
        self.Lockout: LockoutOptions = LockoutOptions()
        """Gets or sets the LockoutOptions for the identity system."""
        self.Password: PasswordOptions = PasswordOptions()
        """Gets or sets the PasswordOptions for the identity system."""
        self.SignIn: SignInOptions = SignInOptions()
        """Gets or sets the SignInOptions for the identity system."""
        self.Tokens: TokenOptions = TokenOptions()
        """Gets or sets the TokenOptions for the identity system."""
        self.User: UserOptions = UserOptions()
        """Gets or sets the UserOptions for the identity system."""
