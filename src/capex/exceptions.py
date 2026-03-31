from __future__ import annotations


class CapexError(Exception):
    """Base exception for all CAPEX-specific errors."""

    def __str__(self) -> str:
        return self.args[0] if self.args else self.__class__.__name__


class ConfigError(CapexError):
    """Raised when configuration files are invalid or inconsistent."""


class ValidationError(CapexError):
    """Raised when runtime or CLI validation fails."""


class CommandExecutionError(CapexError):
    """Raised when an external command fails to execute correctly."""


class CaptureError(CapexError):
    """Raised when packet capture setup or teardown fails."""


class AttackExecutionError(CapexError):
    """Raised when an attack executor fails."""


class RegistryError(CapexError):
    """Raised when attack registry resolution fails."""


class PathError(CapexError):
    """Raised when required files or directories are missing or invalid."""
