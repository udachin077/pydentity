from typing import Optional

from pydentity.identity_error import IdentityError


class IdentityResult:
    def __init__(self, succeeded: bool, *errors: IdentityError):
        self._errors: Optional[tuple[IdentityError, ...]] = errors
        self._succeeded = succeeded

    @property
    def succeeded(self) -> bool:
        return self._succeeded

    @property
    def errors(self) -> tuple[IdentityError, ...]:
        return self._errors

    @staticmethod
    def failed(*errors: IdentityError):
        return IdentityResult(False, *errors)

    @staticmethod
    def success():
        return IdentityResult(True)

    def __str__(self):
        if self.succeeded:
            return f"Succeeded."

        return f"Error: {', '.join(e.code for e in self.errors)}."
