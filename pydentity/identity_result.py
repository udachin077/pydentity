from pydentity.identity_error import IdentityError


class IdentityResult:
    """Represents the result of an identity operation."""

    __slots__ = ('_errors', '_succeeded',)

    def __init__(self, succeeded: bool, *errors: IdentityError) -> None:
        self._errors: tuple[IdentityError, ...] = errors or ()
        self._succeeded = succeeded

    @property
    def succeeded(self) -> bool:
        """Flag indicating whether if the operation succeeded or not."""
        return self._succeeded

    @property
    def errors(self) -> tuple[IdentityError, ...]:
        """An :exc:`Iterable` of :exc:`IdentityError` instances containing errors that occurred during
        the identity operation."""
        return self._errors

    @staticmethod
    def failed(*errors: IdentityError) -> 'IdentityResult':
        """Creates an :exc:`IdentityResult` indicating a failed identity operation,
        with a list of errors if applicable."""
        return IdentityResult(False, *errors)

    @staticmethod
    def success() -> 'IdentityResult':
        """Returns an :exc:`IdentityResult` indicating a successful identity operation."""
        return IdentityResult(True)

    def __str__(self) -> str:
        if self.succeeded:
            return 'Succeeded.'
        return f'Failed: {",".join(e.code for e in self.errors)}.'
