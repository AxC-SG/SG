"""Errors with the persisted release outcome and reason contract."""

class ReleaseError(Exception):
    """A stopped command. outcome and reason follow CD plan 4.4; the default is a refusal before any change."""

    def __init__(self, message, outcome="blocked", reason="refused"):
        super().__init__(message)
        self.outcome, self.reason = outcome, reason
