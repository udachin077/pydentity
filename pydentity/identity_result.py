from collections.abc import Iterable

from pydentity.identity_error import IdentityError

__all__ = ("IdentityResult",)


class IdentityResult:
    """Represents the result of an builders operation."""

    __slots__ = ("_errors", "_succeeded",)

    def __init__(self, succeeded: bool, *errors: IdentityError) -> None:
        self._errors = errors or ()
        self._succeeded = succeeded

    @property
    def succeeded(self) -> bool:
        """Flag indicating whether if the operation succeeded or not."""
        return self._succeeded

    @property
    def errors(self) -> Iterable[IdentityError]:
        """An ``Iterable`` of ``IdentityError`` instances containing errors that occurred during
        the builders operation."""
        return self._errors

    @staticmethod
    def failed(*errors: IdentityError) -> "IdentityResult":
        """Creates an ``IdentityResult`` indicating a failed builders operation,
        with a list of errors if applicable."""
        return IdentityResult(False, *errors)

    @staticmethod
    def success() -> "IdentityResult":
        """Returns an ``IdentityResult`` indicating a successful builders operation."""
        return IdentityResult(True)

    def __str__(self) -> str:
        if self.succeeded:
            return "Succeeded."
        return f"Failed: {",".join(e.code for e in self.errors)}."

    def __repr__(self):
        return f"<{self.__class__.__name__}: {"Succeeded" if self.succeeded else "Failed"}>"
