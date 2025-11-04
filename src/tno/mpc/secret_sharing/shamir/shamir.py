"""
Implement the Shamir secret sharing scheme.
In this scheme, a secret is encoded among the parties in the form of a polynomial.
"""

from __future__ import annotations

import secrets
import sys
from collections.abc import Iterable
from functools import cached_property
from typing import TYPE_CHECKING, Callable

from tno.mpc.encryption_schemes.utils import mod_inv
from tno.mpc.secret_sharing.templates.linear import (
    LinearSecretSharingScheme,
)
from tno.mpc.secret_sharing.templates.threshold import (
    ThresholdSecretSharingScheme,
)

if sys.version_info < (3, 12):
    from typing_extensions import override
else:
    from typing import override

if TYPE_CHECKING:
    from tno.mpc.communication import Pool


SecretTypeT = int
RawSecretTypeT = int
ShareTypeT = int


class ShamirSecretSharingScheme(
    ThresholdSecretSharingScheme[SecretTypeT, RawSecretTypeT, ShareTypeT],
    LinearSecretSharingScheme[SecretTypeT, RawSecretTypeT, ShareTypeT],
):
    r"""
    Class implementing the Shamir secret sharing scheme.

    This is a $t$-out-of-$n$ threshold scheme (where $1 \leq t \leq n$),
    meaning that any subset of at least $t$ parties is able to reconstruct any secret.
    In this scheme, the secret $S$ is encoded among the $n$ parties
    in the form of a degree $(t-1)$ polynomial
    $f(x) = a_0 + a_1 x + a_2 x^2 + \dots + a_{t-1} x^{t-1}$
    such that $f(0)=S$, and every party $1 \leq i \leq n$ owns a share $f(i)$.
    Given any $t$ shares, parties can reconstruct the secret using
    Lagrange interpolation, while guaranteeing that any subset of fewer
    than $t$ shares do not learn anything about the secret.
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        n: int,
        modulus: int,
        threshold: int | None = None,
        pool: Pool | None = None,
    ) -> None:
        threshold = threshold or 1 + n // 2
        LinearSecretSharingScheme.__init__(self, n=n, pool=pool)
        ThresholdSecretSharingScheme.__init__(self, n=n, threshold=threshold, pool=pool)

        self.n = n
        self.modulus = modulus
        self.max_value = modulus // 2
        self.min_value = (-modulus) // 2 + 1

    @cached_property
    def weights(self) -> dict[int, int]:
        r"""
        Calculate the weights needed for reconstruction once.

        Given that the x-coordinate of each party's share
        is fixed at $i+1$, that is the share of party $i$
        is $s_i = f(i+1)$, the interpolation of the polynomial
        simplifies significantly to
        $S = w_0 * s_0 + \dots + w_{n-1} * s_{n-1}$,
        where the $w_i$ are these weights.

        :return: a dictionary containing the weight for each party
        """
        weights = {}
        n_factorial = self._prod(range(1, self.n + 1))
        for i in range(self.n):
            denominator = (i + 1) * self._prod(j - i for j in range(self.n) if j != i)
            weights[i] = n_factorial // denominator
        return weights

    @override
    def empty_shares(self) -> list[int]:
        return [0] * self.nr_parties

    @override
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

    @override
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

    def _generate_polynomial(self, coefficients: list[int]) -> Callable[[int], int]:
        """
        Generate a polynomial from the given coefficients,
        for use during the creation of a secret's shares.

        :param coefficients: the list with coefficients for the polynomial
        :return: a function implementing the polynomial with the given coefficients
        """
        return (
            lambda x: sum(coefficients[i] * x**i for i in range(self.threshold))
            % self.modulus
        )

    @override
    def _share_secret(self, secret: RawSecretTypeT) -> list[ShareTypeT]:
        coefficients = [
            secret,
            *[secrets.randbelow(self.modulus) for i in range(1, self.threshold)],
        ]
        polynomial = self._generate_polynomial(coefficients)
        shares = [polynomial(i + 1) for i in range(self.n)]
        return shares

    @override
    def _add_encoded(self, value1: ShareTypeT, value2: ShareTypeT) -> ShareTypeT:
        return (value1 + value2) % self.modulus

    @override
    def _scalar_add_encoded(
        self, value1: ShareTypeT, value2: RawSecretTypeT
    ) -> ShareTypeT:
        return (value1 + value2) % self.modulus

    @override
    def _scalar_mul_encoded(
        self, value1: ShareTypeT, value2: RawSecretTypeT
    ) -> ShareTypeT:
        return (value1 * value2) % self.modulus

    @override
    async def _mul_encoded(
        self, value1: ShareTypeT, value2: ShareTypeT, resharing_id: str | None = None
    ) -> ShareTypeT:
        r"""
        Multiply two secure numbers with $n$ parties,
        which requires resharing and additional communication.

        A resharing identifier is added, which is unique to each multiplication performed
        during the protocol. This ensures the reshared values are processed for the correct
        multiplication and avoids race conditions.

        If $f(x), g(x)$ encode secrets $a=f(0), b=g(0)$, and are both of degree $t-1$,
        let $h(x)$ = $f(x)g(x)$ so that $h(0) = f(0)g(0)$, but $h$ has degree $2(t-1)$.
        This is a problem, since repeated multiplications all double the degree,
        so at some point the parties can no longer interpolate the result, only having $n$ shares.

        Instead the multiplied value is reshared immediately to keep polynomials of the same degree.
        Each party computes the product of their shares weighted by the interpolation weight
        (given in `self.weights`) and distributes the shares of this value.
        Each party then sums the shares they received
        to get a share representing the desired product $ab$.

        As the degree of the product polynomial is still doubled before it can be reduced,
        it is required that degree $2(t-1)$ polynomials can be interpolated by the parties.
        Such polynomials have $2(t-1)+1 = 2t-1$ degrees of freedom,
        giving the constraint $2t-1 \leq n$ for correct multiplications.

        :param value1: the local party's share of a secret to be multiplied
        :param value2: the local party's share of a secret to be multiplied
        :param resharing_id: a unique identifier for this product
        :raise ValueError: if the scheme's threshold is set too high
        :raise ValueError: if the resharing id is not provided
        :return: the local party's share of the product of the two values
        """
        if 2 * self.threshold - 1 > self.n:
            raise ValueError(
                f"Ciphertext multiplication not possible with n={self.n} parties "
                f"and threshold equal to t={self.threshold}. "
                f"Multiplication requires 2t-1 <= n."
            )

        if resharing_id is None:
            raise ValueError(
                "A resharing_id is required for this scheme and cannot be None."
            )

        index = self.mapping[self.pool.name]
        local_value = (self.weights[index] * value1 * value2) % self.modulus
        resharing = await self.share_and_send(
            f"resharing_{self.pool.name}_{resharing_id}",
            local_value,
            apply_encoding=False,
        )

        result = resharing.get_local_share
        for party in self.all_party_names:
            if party != self.pool.name:
                msg = await self.receive(party, f"resharing_{party}_{resharing_id}")
                result += msg.get_local_share
        return result

    def _prod(self, iterator: Iterable[int]) -> int:
        """
        Give the product of all elements in an iterator.

        :param iterator: the iterator of integers, e.g. a list or tuple
        :return: the product of all values in the iterator
        """
        result = 1
        for value in iterator:
            result *= value
        return result

    @override
    def _reconstruct_raw(
        self, shares: list[ShareTypeT], other_parties: set[str] | None = None
    ) -> RawSecretTypeT:
        """
        Reconstruct a secret from its shares.

        A party wanting to reconstruct a secret must know at least `self.threshold`
        many shares to correctly interpolate the result.

        :param shares: the shares of the secret to be reconstructed
        :param other_parties: a set of other parties with which the
            local party is collaborating to reconstruct the secret;
            if this is `None`, all parties in the pool are collaborating
        :return: the reconstructed secret
        """
        if other_parties is None:
            return (
                sum(self.weights[i] * shares[i] for i in range(self.n)) % self.modulus
            )

        contributors = [
            self.mapping[party] for party in other_parties.union({self.pool.name})
        ]
        partial_weights = {}
        numerator = self._prod([c + 1 for c in contributors])
        for i in contributors:
            denominator = (i + 1) * self._prod(j - i for j in contributors if j != i)
            partial_weights[i] = numerator * mod_inv(denominator, self.modulus)

        return (
            int(sum(partial_weights[i] * shares[i] for i in contributors))
            % self.modulus
        )

    @override
    def __hash__(self) -> int:
        return hash((self.n, self.modulus, self.threshold))

    @override
    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}"
            f"(n={self.n}, modulus={self.modulus}, threshold={self.threshold})"
        )
