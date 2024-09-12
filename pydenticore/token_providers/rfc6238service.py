import base64

import pyotp

__all__ = (
    "generate_code",
    "validate_code",
)


def _apply_modifier(input_: bytes, modifier_bytes: bytes | None = None) -> str:
    return base64.b32encode(input_ + modifier_bytes if modifier_bytes else input_).decode()


def _create_totp(security_token: bytes, modifier: bytes | None = None, interval: int = 30) -> pyotp.TOTP:
    return pyotp.TOTP(_apply_modifier(security_token, modifier), interval=interval)


class Rfc6238AuthenticationService:

    @staticmethod
    def generate_code(security_token: bytes, modifier: bytes | None = None, interval: int = 30) -> str:
        return _create_totp(security_token, modifier, interval).now()

    @staticmethod
    def validate_code(security_token: bytes, code: str, modifier: bytes | None = None, interval: int = 30) -> bool:
        return _create_totp(security_token, modifier, interval).verify(code)


generate_code = Rfc6238AuthenticationService.generate_code
validate_code = Rfc6238AuthenticationService.validate_code
