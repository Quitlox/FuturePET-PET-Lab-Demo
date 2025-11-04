"""
Test module for the Shamir secret sharing scheme.

It tests all combinations of arguments in the
`LINEAR_FUNCTIONS` and `INPUT_TRIPLETS` fixtures.
Note that all input as well as output values must be in the allowed range
`[-modulus // 2, modulus // 2)`, where the modulus is defined by the scheme.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable

import pytest

from tno.mpc.communication import Pool
from tno.mpc.secret_sharing.shamir.shamir import (
    ShamirSecretSharingScheme,
)
from tno.mpc.secret_sharing.templates.base import SecureNumber

SSS_TEST_MODULUS = 1679
SN = SecureNumber[Any, Any, Any]
SSSS = ShamirSecretSharingScheme


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

THRESHOLD_VALUES = (1, 2, 3)

RECONSTRUCTING_PARTIES = [
    ("local0", "local1", "local2"),
    ("local0", "local1"),
    ("local0", "local2"),
    ("local1", "local2"),
]

INPUT_MULTIPLICATIONS = [
    lambda x, y, z: (x,),
    lambda x, y, z: (x, y),
    lambda x, y, z: (z, z),
    lambda x, y, z: (z, y, x),
    lambda x, y, z: (x, y, x, z, y, y),
]


@pytest.fixture(name="scheme_3p")
def fixture_scheme_3p(mock_pool_trio: tuple[Pool, Pool, Pool]) -> Any:
    """
    Creates a collection of 3 communication pools

    :param mock_pool_trio: a tuple of three mock pools
    :return: a collection of communication pools
    """
    return [
        ShamirSecretSharingScheme(3, SSS_TEST_MODULUS, pool=pool)
        for i, pool in enumerate(mock_pool_trio)
    ]


@pytest.fixture(params=THRESHOLD_VALUES, name="scheme_threshold")
def fixture_threshold_scheme(
    mock_pool_trio: tuple[Pool, Pool, Pool], request: pytest.FixtureRequest
) -> Any:
    """
    Creates a collection of 3 communication pools corresponding to a
    secret sharing scheme with a given threshold

    :param mock_pool_trio: a tuple of three mock pools
    :param request: a request containing the scheme's threshold
    :return: a collection of communication pools
    """
    yield [
        ShamirSecretSharingScheme(3, 1679, threshold=request.param, pool=pool)
        for i, pool in enumerate(mock_pool_trio)
    ]


@pytest.mark.parametrize("linear_function", LINEAR_FUNCTIONS)
@pytest.mark.parametrize("party_values", INPUT_TRIPLETS)
@pytest.mark.asyncio
async def test_online_calculation(
    scheme_3p: tuple[SSSS, SSSS, SSSS],
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


@pytest.mark.parametrize("reconstructors", RECONSTRUCTING_PARTIES)
@pytest.mark.asyncio
async def test_online_threshold(
    scheme_threshold: tuple[SSSS, SSSS, SSSS],
    reconstructors: tuple[str],
) -> None:
    """
    Test whether the threshold works correctly; if there are at least
    scheme.threshold parties to reconstruct, the reconstruction must succeed.

    :param scheme_threshold: the scheme containing three parties and a given threshold
    :param reconstructors: fixture containing which parties attempt to reconstruct the secret
    """

    if len(reconstructors) < scheme_threshold[0].threshold:
        return

    value_alice = 23

    async def alice() -> None:
        scheme = scheme_threshold[0]

        # Share secret
        secret_alice = await scheme.share_and_send("secret_alice", value_alice)

        if "local0" not in reconstructors:
            return

        other_parties = {party for party in reconstructors if party != "local0"}
        plain_alice = await secret_alice.exchange_and_reconstruct(
            other_parties=other_parties
        )
        assert plain_alice == value_alice
        return

    async def bob() -> None:
        scheme = scheme_threshold[1]

        # Receive secret
        secret_alice = await scheme.receive("local0", "secret_alice")

        if "local1" not in reconstructors:
            return

        other_parties = {party for party in reconstructors if party != "local1"}
        plain_alice = await secret_alice.exchange_and_reconstruct(
            other_parties=other_parties
        )
        assert plain_alice == value_alice
        return

    async def charlie() -> None:
        scheme = scheme_threshold[2]

        # Receive secret
        secret_alice = await scheme.receive("local0", "secret_alice")

        if "local2" not in reconstructors:
            return

        other_parties = {party for party in reconstructors if party != "local2"}
        plain_alice = await secret_alice.exchange_and_reconstruct(
            other_parties=other_parties
        )
        assert plain_alice == value_alice
        return

    await asyncio.gather(alice(), bob(), charlie())


@pytest.mark.parametrize("reconstructors", RECONSTRUCTING_PARTIES)
@pytest.mark.asyncio
async def test_online_threshold_with_insufficient_parties(
    scheme_threshold: tuple[SSSS, SSSS, SSSS],
    reconstructors: tuple[str],
) -> None:
    """
    Test whether the threshold works correctly; if there are fewer than
    scheme.threshold parties to reconstruct, the reconstruction must fail.

    :param scheme_threshold: the scheme containing three parties and a given threshold
    :param reconstructors: fixture containing which parties attempt to reconstruct the secret
    """

    reconstructor_count = len(reconstructors)
    if reconstructor_count >= scheme_threshold[0].threshold:
        return

    value_alice = 23

    async def alice() -> None:
        scheme = scheme_threshold[0]

        # Share secret
        secret_alice = await scheme.share_and_send("secret_alice", value_alice)

        if "local0" not in reconstructors:
            return

        other_parties = {party for party in reconstructors if party != "local0"}
        with pytest.raises(
            ValueError,
            match=(
                f"The scheme's threshold is {scheme.threshold}, "
                f"but only {reconstructor_count} were supplied"
            ),
        ):
            await secret_alice.exchange_and_reconstruct(other_parties=other_parties)

    async def bob() -> None:
        scheme = scheme_threshold[1]

        # Receive secret
        secret_alice = await scheme.receive("local0", "secret_alice")

        if "local1" not in reconstructors:
            return

        other_parties = {party for party in reconstructors if party != "local1"}
        with pytest.raises(
            ValueError,
            match=(
                f"The scheme's threshold is {scheme.threshold}, "
                f"but only {reconstructor_count} were supplied"
            ),
        ):
            await secret_alice.exchange_and_reconstruct(other_parties=other_parties)

    async def charlie() -> None:
        scheme = scheme_threshold[2]

        # Receive secret
        secret_alice = await scheme.receive("local0", "secret_alice")

        if "local2" not in reconstructors:
            return

        other_parties = {party for party in reconstructors if party != "local2"}
        with pytest.raises(
            ValueError,
            match=(
                f"The scheme's threshold is {scheme.threshold}, "
                f"but only {reconstructor_count} were supplied"
            ),
        ):
            await secret_alice.exchange_and_reconstruct(other_parties=other_parties)

    await asyncio.gather(alice(), bob(), charlie())


@pytest.mark.parametrize("multiplication_inputs", INPUT_MULTIPLICATIONS)
@pytest.mark.parametrize("party_values", INPUT_TRIPLETS)
@pytest.mark.asyncio
async def test_online_multiplication(
    scheme_3p: tuple[SSSS, SSSS, SSSS],
    multiplication_inputs: Callable[[SN | int, SN | int, SN | int], tuple[int]],
    party_values: tuple[int, int, int],
) -> None:
    """
    Test all combinations of calculations and values using the scheme
    versus the known correct result

    :param scheme_3p: the scheme containing three parties
    :param multiplication_inputs: fixture containing inputs to be multiplied together
    :param party_values: fixture containing all inputs to be calculated with
    """

    value_alice, value_bob, value_charlie = party_values
    multiplicands = multiplication_inputs(value_alice, value_bob, value_charlie)

    async def alice() -> None:
        scheme = scheme_3p[0]

        # Share secret
        secret_alice = await scheme.share_and_send("secret_alice", value_alice)

        # Receive other secrets
        secret_bob = await scheme.receive("local1", "secret_bob")
        secret_charlie = await scheme.receive("local2", "secret_charlie")

        secure_inputs = multiplication_inputs(secret_alice, secret_bob, secret_charlie)
        secret_result = secure_inputs[0]
        secure_input: SN
        for secure_input in secure_inputs[1:]:
            assert isinstance(secret_result, SecureNumber)
            secret_result = await scheme.mul(secret_result, secure_input)
        assert isinstance(secret_result, SecureNumber)
        plain_result = await secret_result.exchange_and_reconstruct()
        clear_result = multiplicands[0]
        for multiplicand in multiplicands[1:]:
            clear_result = (clear_result * multiplicand) % scheme.modulus
        reduced_clear_result = (
            clear_result
            if clear_result <= scheme.max_value
            else clear_result - scheme.modulus
        )
        assert plain_result == reduced_clear_result

    async def bob() -> None:
        scheme = scheme_3p[1]

        # Share secret
        secret_bob = await scheme.share_and_send("secret_bob", value_bob)

        # Receive other secrets
        secret_alice = await scheme.receive("local0", "secret_alice")
        secret_charlie = await scheme.receive("local2", "secret_charlie")

        secure_inputs = multiplication_inputs(secret_alice, secret_bob, secret_charlie)
        secret_result = secure_inputs[0]
        secure_input: SN
        for secure_input in secure_inputs[1:]:
            assert isinstance(secret_result, SecureNumber)
            secret_result = await scheme.mul(secret_result, secure_input)
        assert isinstance(secret_result, SecureNumber)
        plain_result = await secret_result.exchange_and_reconstruct()
        clear_result = multiplicands[0]
        for multiplicand in multiplicands[1:]:
            clear_result = (clear_result * multiplicand) % scheme.modulus
        reduced_clear_result = (
            clear_result
            if clear_result <= scheme.max_value
            else clear_result - scheme.modulus
        )
        assert plain_result == reduced_clear_result

    async def charlie() -> None:
        scheme = scheme_3p[2]

        # Share secret
        secret_charlie = await scheme.share_and_send("secret_charlie", value_charlie)

        # Receive other secrets
        secret_alice = await scheme.receive("local0", "secret_alice")
        secret_bob = await scheme.receive("local1", "secret_bob")

        secure_inputs = multiplication_inputs(secret_alice, secret_bob, secret_charlie)
        secret_result = secure_inputs[0]
        secure_input: SN
        for secure_input in secure_inputs[1:]:
            assert isinstance(secret_result, SecureNumber)
            secret_result = await scheme.mul(secret_result, secure_input)
        assert isinstance(secret_result, SecureNumber)
        plain_result = await secret_result.exchange_and_reconstruct()
        clear_result = multiplicands[0]
        for multiplicand in multiplicands[1:]:
            clear_result = (clear_result * multiplicand) % scheme.modulus
        reduced_clear_result = (
            clear_result
            if clear_result <= scheme.max_value
            else clear_result - scheme.modulus
        )
        assert plain_result == reduced_clear_result

    await asyncio.gather(alice(), bob(), charlie())
