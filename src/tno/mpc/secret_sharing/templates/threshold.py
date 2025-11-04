import sys
from typing import Generic

from tno.mpc.secret_sharing.templates.base import SecretSharingScheme
from tno.mpc.secret_sharing.templates.utils import (
    RawSecretTypeT,
    SecretTypeT,
    ShareTypeT,
)

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self
if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

COMMUNICATION_INSTALLED = False
try:
    from tno.mpc.communication import Pool

    COMMUNICATION_INSTALLED = True
except ImportError:
    pass


class ThresholdSecretSharingScheme(
    SecretSharingScheme[SecretTypeT, RawSecretTypeT, ShareTypeT],
    Generic[SecretTypeT, RawSecretTypeT, ShareTypeT],
):
    r"""
    Base class for threshold secret sharing schemes.

    A threshold scheme has $n$ parties participating,
    but also a (predefined) threshold $t$ with $1 \leq t \leq n$,
    which is used for reconstruction of a secret.
    Namely, any subset of at least $t$ parties can reconstruct any secret
    without knowledge or approval of the remaining parties.
    Any subset of fewer than $t$ parties can still learn nothing about any secret.
    """

    def __init__(self, n: int, threshold: int, pool: Pool | None = None) -> None:
        super().__init__(n=n, pool=pool)
        self.threshold = threshold
        """The minimum number of parties required to reconstruct the secret."""

    @override
    def _reconstruct(
        self: Self,
        shares: list[ShareTypeT],
        apply_encoding: bool = True,
        other_parties: set[str] | None = None,
    ) -> SecretTypeT:
        if other_parties and (num_parties := len(other_parties) + 1) < self.threshold:
            raise ValueError(
                f"The scheme's threshold is {self.threshold}, "
                f"but only {num_parties} were supplied"
            )
        return super()._reconstruct(shares, apply_encoding, other_parties)
