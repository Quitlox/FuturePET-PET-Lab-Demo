"""
General utilities for secret sharing.
"""

from abc import abstractmethod
from typing import Any, Protocol, TypeVar, runtime_checkable

T_co = TypeVar("T_co", covariant=True)


@runtime_checkable
class SupportsNeg(Protocol[T_co]):  # pylint: disable=too-few-public-methods
    """
    An ABC with one abstract method __neg__.

    Protocol used to check if a class supports negation.
    """

    __slots__ = ()

    @abstractmethod
    def __neg__(self) -> T_co:
        pass


SecretTypeT = TypeVar("SecretTypeT")
"""Accepted input types that the secret sharing scheme can handle."""
RawSecretTypeT = TypeVar("RawSecretTypeT", bound=SupportsNeg[Any])
"""Type of the raw secret after encoding, i.e. the type that the secret sharing scheme expects."""
ShareTypeT = TypeVar("ShareTypeT")
"""Type of the share(s) of a single party."""
