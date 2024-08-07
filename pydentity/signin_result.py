class SignInResult:
    __slots__ = ('_succeeded', '_is_locked_out', '_is_not_allowed', '_requires_two_factor',)

    def __init__(
            self,
            succeeded: bool = False,
            is_locked_out: bool = False,
            is_not_allowed: bool = False,
            requires_two_factor: bool = False
    ):
        self._succeeded = succeeded
        self._is_locked_out = is_locked_out
        self._is_not_allowed = is_not_allowed
        self._requires_two_factor = requires_two_factor

    @property
    def is_locked_out(self):
        return self._is_locked_out

    @property
    def succeeded(self):
        return self._succeeded

    @property
    def is_not_allowed(self):
        return self._is_not_allowed

    @property
    def requires_two_factor(self):
        return self._requires_two_factor

    @staticmethod
    def success():
        return SignInResult(succeeded=True)

    @staticmethod
    def locked_out():
        return SignInResult(is_locked_out=True)

    @staticmethod
    def not_allowed():
        return SignInResult(is_not_allowed=True)

    @staticmethod
    def two_factor_required():
        return SignInResult(requires_two_factor=True)

    @staticmethod
    def failed():
        return SignInResult()

    def __str__(self):
        if self._is_locked_out:
            return 'Locked out'
        if self.is_not_allowed:
            return 'Not Allowed'
        if self.requires_two_factor:
            return 'Requires Two-Factor'
        if self._succeeded:
            return 'Succeeded'
        return 'Failed'
