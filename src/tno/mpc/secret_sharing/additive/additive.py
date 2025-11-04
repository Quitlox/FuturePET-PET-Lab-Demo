r"""
Implement the additive secret sharing scheme. In this scheme, the secret $S$ is
simply split among $n$ parties by making the sum of the shares equal to the
secret, i.e. $S = s_1 + s_2 + ... + s_n (\mod \text{modulus})$
"""

from __future__ import annotations

import logging
import secrets
from typing import TYPE_CHECKING

from tno.mpc.secret_sharing.templates.linear import (
    LinearSecretSharingScheme,
)

if TYPE_CHECKING:
    from tno.mpc.communication import Pool

logger = logging.getLogger(__name__)


SecretTypeT = int
RawSecretTypeT = int
ShareTypeT = int


class AdditiveSecretSharingScheme(
    LinearSecretSharingScheme[SecretTypeT, RawSecretTypeT, ShareTypeT]
):
    r"""
    Class implementing the additive secret sharing scheme.

    In this scheme, the secret $S$ is simply split among $n$ parties
    Party $i$ is given the share $s_i$ in such a way that
    the sum of all shares are equal to the secret, i.e.
    $S = s_1 + s_2 + ... + s_n (\mod \text{modulus})$
    Note that even knowing all but one share of a secret tells us nothing about
    that secret, as each possible value of the last share would lead to a
    different unique secret.
    """

    def __init__(
        self,
        n: int,
        modulus: int,
        pool: Pool | None = None,
    ) -> None:
        super().__init__(n=n, pool=pool)

        self.modulus = modulus
        self.max_value = modulus // 2
        self.min_value = (-modulus) // 2 + 1

    def encode(self, value: SecretTypeT) -> RawSecretTypeT:
        """
        Encode a supported value using the specified scheme.

        :param value: value to be encoded
        :raise ValueError: if value is outside of supported range
        :return: the encoded value
        """
        if not self.min_value <= value <= self.max_value:
            raise ValueError(
                f"This encoding scheme only supports values in the range [{self.min_value};"
                f"{self.max_value}], {value} is outside that range."
            )
        return value % self.modulus

    def decode(self, encoded_value: RawSecretTypeT) -> SecretTypeT:
        """
        Decode an encoded value.

        :param encoded_value: encoded value to be decoded
        :return: the decoded value
        """
        return (
            encoded_value
            if encoded_value <= self.max_value
            else encoded_value - self.modulus
        )

    def empty_shares(self) -> list[ShareTypeT]:
        return [0] * self.nr_parties

    def _share_secret(self, secret: RawSecretTypeT) -> list[ShareTypeT]:
        # All shares belonging to other parties are compeletely random
        shares = [
            (secrets.randbelow(self.modulus)) % self.modulus
            for i in range(1, self.nr_parties)
        ]
        # The party's own share ensures correctness
        shares = [(secret - sum(shares)) % self.modulus, *shares]
        return shares

    def _add_encoded(self, value1: ShareTypeT, value2: ShareTypeT) -> ShareTypeT:
        return (value1 + value2) % self.modulus

    def _scalar_add_encoded(
        self, value1: ShareTypeT, value2: RawSecretTypeT
    ) -> ShareTypeT:
        if self.mapping[self.pool.name] == 0:
            return (value1 + value2) % self.modulus
        return value1

    async def _mul_encoded(
        self, value1: ShareTypeT, value2: ShareTypeT, resharing_id: str | None = None
    ) -> ShareTypeT:
        raise NotImplementedError(
            f"{self.__class__.__name__} does not yet support ciphertext multiplication."
        )

    def _scalar_mul_encoded(
        self, value1: ShareTypeT, value2: RawSecretTypeT
    ) -> ShareTypeT:
        return (value1 * value2) % self.modulus

    def _reconstruct_raw(
        self, shares: list[ShareTypeT], other_parties: set[str] | None = None
    ) -> RawSecretTypeT:
        if other_parties is not None:
            raise ValueError(
                "This is not a threshold scheme, "
                "so `other_parties` should always be the default None"
            )
        # By construction, the sum of the shares is equal to the secret
        return (sum(shares)) % self.modulus

    def __hash__(self) -> int:
        return hash((self.nr_parties, self.modulus))

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(n={self.nr_parties}, modulus={self.modulus})"
