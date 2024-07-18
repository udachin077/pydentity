from typing import Optional

from pydentity.abc import ILookupNormalizer


class UpperLookupNormalizer(ILookupNormalizer):
    """Converting keys to their upper case representation."""

    def normalize_email(self, email: Optional[str]) -> Optional[str]:
        return email.upper() if email else email

    def normalize_name(self, name: Optional[str]) -> Optional[str]:
        return name.upper() if name else name


class LowerLookupNormalizer(ILookupNormalizer):
    """Converting keys to their lower case representation."""

    def normalize_email(self, email: Optional[str]) -> Optional[str]:
        return email.lower() if email else email

    def normalize_name(self, name: Optional[str]) -> Optional[str]:
        return name.lower() if name else name
