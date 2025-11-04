"""
Test of the general secret sharing scheme.
It tests the general functionality of sharing, sending, receiving, and reconstructing values.
For this we use a dummy (and insecure) scheme where a party sets their share equal to the secret.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from tno.mpc.communication import Pool
from tno.mpc.secret_sharing.templates.base import (
    SecretSharingScheme,
    SecureNumber,
)

logger = logging.getLogger(__name__)

SN = SecureNumber[Any, Any, Any]
SSS = SecretSharingScheme[SN, Any, Any]

SecretTypeT = Any
RawSecretTypeT = Any
ShareTypeT = Any


class DummySecretSharingScheme(
    SecretSharingScheme[SecretTypeT, RawSecretTypeT, ShareTypeT]
):
    """
    Dummy secret sharing scheme for general testing.
    This scheme should not be used for other purposes,
    as we simply make the share of the secret's owner
    equal to the entire secret and set all other shares
    to a dummy string, "not used".
    This means that the scheme is not secure at all.
    """

    def encode(self, value: SecretTypeT) -> RawSecretTypeT:
        """
        Encode a supported value using the specified scheme.

        :param value: value to be encoded
        :return: the encoded value
        """
        return value

    def decode(self, encoded_value: RawSecretTypeT) -> SecretTypeT:
        """
        Decode an encoded value.

        :param encoded_value: encoded value to be decoded
        :return: the decoded value
        """
        return encoded_value

    def empty_shares(self) -> list[ShareTypeT]:
        return [None] * self.nr_parties

    def _share_secret(self, secret: RawSecretTypeT) -> list[ShareTypeT]:
        shares = ["not used" for i in range(0, self.nr_parties)]
        shares[0] = secret
        return shares

    def _reconstruct_raw(
        self, shares: list[ShareTypeT], other_parties: set[str] | None = None
    ) -> RawSecretTypeT:
        return [share for share in shares if share != "not used"][0]

    def _add_encoded(self, value1: ShareTypeT, value2: ShareTypeT) -> ShareTypeT:
        raise NotImplementedError()

    def _scalar_add_encoded(
        self, value1: ShareTypeT, value2: RawSecretTypeT
    ) -> ShareTypeT:
        raise NotImplementedError()

    async def _mul_encoded(self, value1: ShareTypeT, value2: ShareTypeT) -> ShareTypeT:
        raise NotImplementedError()

    def _scalar_mul_encoded(
        self, value1: ShareTypeT, value2: RawSecretTypeT
    ) -> ShareTypeT:
        raise NotImplementedError()


@pytest.fixture(name="scheme_3p")
def fixture_scheme_3p(mock_pool_trio: tuple[Pool, Pool, Pool]) -> Any:
    """
    Creates a collection of 3 communication pools

    :param mock_pool_trio: a tuple of three mock pools
    :return: a collection of communication pools
    """
    return [DummySecretSharingScheme(3, pool) for i, pool in enumerate(mock_pool_trio)]


@pytest.mark.asyncio
async def test_send_and_receive(scheme_3p: tuple[SSS, SSS, SSS]) -> None:
    """
    Test the basic sending and receiving of secret shares.

    :param scheme_3p: the scheme containing three parties
    """

    p1, p2, p3 = scheme_3p
    value_to_share = 42
    shares_p1 = await p1.share_and_send("answer", value_to_share, apply_encoding=False)

    share_p2 = await p2.receive("local0", "answer")
    assert p2.get_share(share_p2.shares, p2.pool.name) == p1.get_share(
        shares_p1.shares, p2.pool.name
    )

    share_p3 = await p3.receive("local0", "answer")
    assert p3.get_share(share_p3.shares, p3.pool.name) == p1.get_share(
        shares_p1.shares, p3.pool.name
    )


@pytest.mark.asyncio
async def test_exchange_and_reconstruct(scheme_3p: tuple[SSS, SSS, SSS]) -> None:
    """
    Test the basic exchanging and reconstructing of secret shares.

    :param scheme_3p: the scheme containing three parties
    """
    value_to_share = 42

    async def alice() -> None:
        p1 = scheme_3p[0]

        shares_p1 = await p1.share_and_send("answer", value_to_share)
        result_p1 = await shares_p1.exchange_and_reconstruct()
        assert isinstance(result_p1, int) and result_p1 == value_to_share

    async def bob() -> None:
        p2 = scheme_3p[1]

        share_p2 = await p2.receive("local0", "answer")
        result_p2 = await share_p2.exchange_and_reconstruct()
        assert isinstance(result_p2, int) and result_p2 == value_to_share

    async def charlie() -> None:
        p3 = scheme_3p[2]

        share_p3 = await p3.receive("local0", "answer")
        result_p3 = await share_p3.exchange_and_reconstruct()
        assert isinstance(result_p3, int) and result_p3 == value_to_share

    await asyncio.gather(alice(), bob(), charlie())
