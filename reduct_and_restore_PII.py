"""Backwards-compatible entry point for the PII middleware.

The implementation now lives in the ``pii`` package; this module keeps the
original import path working.
"""

from pii import PIIMiddleware

__all__ = ["PIIMiddleware"]
