"""
Test of the additive secret sharing scheme.

It tests all combinations of arguments in the `LINEAR_FUNCTIONS` and
`INPUT_TRIPLETS` fixtures.

Note that all input as well as output values must be in the allowed range
`[-modulus // 2, modulus // 2)`, where the modulus is defined by the scheme.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

import pytest

from tno.mpc.communication import Pool
from tno.mpc.secret_sharing.additive import AdditiveSecretSharingScheme
from tno.mpc.secret_sharing.templates.base import SecureNumber

logger = logging.getLogger(__name__)

SSS_TEST_MODULUS = 1679
SN = SecureNumber[Any, Any, Any]
ASSS = AdditiveSecretSharingScheme

ENCODING_VALID = (
    list(range(-SSS_TEST_MODULUS // 2 + 1, -SSS_TEST_MODULUS // 2 + 3))
    + list(range(-3, 3))
    + list(range(SSS_TEST_MODULUS // 2 - 3, SSS_TEST_MODULUS // 2))
)

ENCODING_INVALID = (
    list(range(-SSS_TEST_MODULUS - 3, -SSS_TEST_MODULUS + 3))
    + list(range(-SSS_TEST_MODULUS // 2 - 3, -SSS_TEST_MODULUS // 2))
    + list(range(SSS_TEST_MODULUS // 2 + 1, SSS_TEST_MODULUS // 2 + 3))
)


LINEAR_FUNCTIONS = [
    lambda x, y, z: x + y,
    lambda x, y, z: x + 7,
    lambda x, y, z: 7 + x,
    lambda x, y, z: -y,
    lambda x, y, z: y - z,
    lambda x, y, z: y - 7,
    lambda x, y, z: 7 - z,
    lambda x, y, z: 7 * z,
    lambda x, y, z: z * 7,
    lambda x, y, z: -x + 2 * y - (z + 1),
    lambda x, y, z: 3 * (z - 1) - y + 2,
]


INPUT_TRIPLETS = [
    (17, 29, 61),
    (4, 0, 1),
    (-5, 11, -23),
    (97, -314, 41),
]


@pytest.fixture(name="scheme_3p")
def fixture_scheme_3p(mock_pool_trio: tuple[Pool, Pool, Pool]) -> Any:
    """
    Creates a collection of 3 communication pools

    :param mock_pool_trio: a tuple of three mock pools
    :return: a collection of communication pools
    """
    return [
        AdditiveSecretSharingScheme(3, SSS_TEST_MODULUS, pool)
        for i, pool in enumerate(mock_pool_trio)
    ]


@pytest.mark.parametrize("constant", ENCODING_VALID)
def test_encoding_valid(scheme_3p: tuple[ASSS, ASSS, ASSS], constant: int) -> None:
    """
    Test the basic sending and receiving of secret shares.

    :param scheme_3p: the scheme containing three parties
    """

    scheme, _, _ = scheme_3p
    encoded_value = scheme.encode(constant)
    decoded_value = scheme.decode(encoded_value)
    assert decoded_value == constant


@pytest.mark.parametrize("constant", ENCODING_INVALID)
def test_encoding_invalid(scheme_3p: tuple[ASSS, ASSS, ASSS], constant: int) -> None:
    scheme, _, _ = scheme_3p

    with pytest.raises(
        ValueError,
        match=f"This encoding scheme only supports values in the range \\[{scheme.min_value};"
        f"{scheme.max_value}\\], {constant} is outside that range.",
    ):
        scheme.encode(constant)


@pytest.mark.parametrize("linear_function", LINEAR_FUNCTIONS)
@pytest.mark.parametrize("party_values", INPUT_TRIPLETS)
@pytest.mark.asyncio
async def test_online_calculation(
    scheme_3p: tuple[ASSS, ASSS, ASSS],
    linear_function: Callable[[SN | int, SN | int, SN | int], SN | int],
    party_values: tuple[int, int, int],
) -> None:
    """
    Test all combinations of calculations and values using the scheme
    versus the known correct result

    :param scheme_3p: the scheme containing three parties
    :param linear_function: fixture containing all functions to be calculated
    :param party_values: fixture containing all inputs to be calculated with
    """

    value_alice, value_bob, value_charlie = party_values

    async def alice() -> None:
        scheme = scheme_3p[0]

        # Share secret
        secret_alice = await scheme.share_and_send("secret_alice", value_alice)

        # Receive other secrets
        secret_bob = await scheme.receive("local1", "secret_bob")
        secret_charlie = await scheme.receive("local2", "secret_charlie")

        secret_result = linear_function(secret_alice, secret_bob, secret_charlie)
        assert isinstance(secret_result, SecureNumber)
        plain_result = await secret_result.exchange_and_reconstruct()
        assert plain_result == linear_function(value_alice, value_bob, value_charlie)

    async def bob() -> None:
        scheme = scheme_3p[1]

        # Share secret
        secret_bob = await scheme.share_and_send("secret_bob", value_bob)

        # Receive other secrets
        secret_alice = await scheme.receive("local0", "secret_alice")
        secret_charlie = await scheme.receive("local2", "secret_charlie")

        secret_result = linear_function(secret_alice, secret_bob, secret_charlie)
        assert isinstance(secret_result, SecureNumber)
        plain_result = await secret_result.exchange_and_reconstruct()
        assert plain_result == linear_function(value_alice, value_bob, value_charlie)

    async def charlie() -> None:
        scheme = scheme_3p[2]

        # Share secret
        secret_charlie = await scheme.share_and_send("secret_charlie", value_charlie)

        # Receive other secrets
        secret_alice = await scheme.receive("local0", "secret_alice")
        secret_bob = await scheme.receive("local1", "secret_bob")

        secret_result = linear_function(secret_alice, secret_bob, secret_charlie)
        assert isinstance(secret_result, SecureNumber)
        plain_result = await secret_result.exchange_and_reconstruct()
        assert plain_result == linear_function(value_alice, value_bob, value_charlie)

    await asyncio.gather(alice(), bob(), charlie())
