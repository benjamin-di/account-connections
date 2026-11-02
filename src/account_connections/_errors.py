"""Shared closed-error type, without importing a platform storage backend."""


class StateError(Exception):
    """Missing, unreadable or stale authority; hosts map this to a closed error."""

    def __init__(self, code: str = "connection_disconnected"):
        self.code = code
        super().__init__(code)
