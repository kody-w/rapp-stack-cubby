"""Application error types."""


class RappStackCubbyError(Exception):
    """Base class for expected application errors."""


class RepositoryNotFoundError(RappStackCubbyError):
    """Raised when a repository root cannot be located."""


class UnsafePathError(RappStackCubbyError):
    """Raised when a path escapes the selected repository."""


class ContractReadError(RappStackCubbyError):
    """Raised when a contract document cannot be read or decoded."""


class VerificationError(RappStackCubbyError):
    """Raised when verified contract data is required but invalid."""
