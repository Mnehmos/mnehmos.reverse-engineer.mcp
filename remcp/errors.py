"""Typed errors for the RE engine.

First principle: a library never calls SystemExit. SystemExit is a
BaseException, so it escapes `except Exception` handlers -- including the one
in FastMCP's tool wrapper -- and takes the whole server down with it. Every
failure mode in this package raises an ordinary Exception subclass so the
tool layer can convert it into a structured error envelope.
"""
from __future__ import annotations


class ReError(Exception):
    """Base class for every error this package raises."""

    code = "re_error"

    def __init__(self, message: str, **context: object) -> None:
        super().__init__(message)
        self.message = message
        self.context = context

    def to_dict(self) -> dict:
        return {"ok": False, "error": {"code": self.code, "message": self.message, **self.context}}


class TargetError(ReError):
    """The target path is missing, unreadable, too large, or not a file."""

    code = "target_error"


class FormatError(ReError):
    """The bytes do not parse as the container format they claim to be."""

    code = "format_error"


class UnsupportedError(ReError):
    """A real capability gap: this format/architecture is not implemented.

    Raised deliberately instead of returning garbage. The audited predecessor
    disassembled 64-bit images with a hardcoded 32-bit decoder and returned
    1,187 fabricated call edges with no warning; refusing is strictly better.
    """

    code = "unsupported"


class AddressError(ReError):
    """An address does not map into the image, or maps into a gap."""

    code = "address_error"


class PolicyError(ReError):
    """A knowledge-base write violated the confidence policy."""

    code = "policy_error"


class CacheError(ReError):
    """The analysis cache could not be read or written."""

    code = "cache_error"
