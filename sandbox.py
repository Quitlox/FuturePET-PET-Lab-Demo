"""
Workshop Sandbox - Experiment with Homomorphic Encryption and Secret Sharing

This file provides boilerplate code for setting up three-party communication.
Look for the "YOUR CODE HERE" comments to start experimenting!
"""

import asyncio

from tno.mpc.communication import Pool
from tno.mpc.communication.communicators.communicator import Communicator
from tno.mpc.communication.communicators.http_communicator import (
    HttpCommunicator,
    HttpConnection,
)
from tno.mpc.encryption_schemes.paillier import Paillier
from tno.mpc.encryption_schemes.paillier.paillier import PaillierCiphertext
from tno.mpc.secret_sharing.shamir import ShamirSecretSharingScheme


# =============================================================================
# COMMUNICATION SETUP (Already configured for you!)
# =============================================================================


async def setup_three_pools() -> tuple[Pool, Pool, Pool]:
    """
    Sets up communication pools for three parties: Alice, Bob, and Charlie.
    Each party can send and receive messages from the others.
    """
    # Create Pool and Communicator for Alice
    comm_alice: Communicator = HttpCommunicator(addr="localhost", port=8100)
    pool_alice = Pool("alice", comm_alice)

    # Create Pool and Communicator for Bob
    comm_bob: Communicator = HttpCommunicator(addr="localhost", port=8101)
    pool_bob = Pool("bob", comm_bob)

    # Create Pool and Communicator for Charlie
    comm_charlie: Communicator = HttpCommunicator(addr="localhost", port=8102)
    pool_charlie = Pool("charlie", comm_charlie)

    # Add connections between all parties
    pool_alice.add_client(name="bob", connection=HttpConnection(addr="localhost", port=8101))
    pool_alice.add_client(name="charlie", connection=HttpConnection(addr="localhost", port=8102))
    pool_bob.add_client(name="alice", connection=HttpConnection(addr="localhost", port=8100))
    pool_bob.add_client(name="charlie", connection=HttpConnection(addr="localhost", port=8102))
    pool_charlie.add_client(name="alice", connection=HttpConnection(addr="localhost", port=8100))
    pool_charlie.add_client(name="bob", connection=HttpConnection(addr="localhost", port=8101))

    # Initialize all pools
    await pool_alice.initialize()
    await pool_bob.initialize()
    await pool_charlie.initialize()

    return pool_alice, pool_bob, pool_charlie


# =============================================================================
# HOMOMORPHIC ENCRYPTION EXPERIMENT
# =============================================================================


async def experiment_homomorphic_encryption() -> None:
    """
    Experiment with Paillier homomorphic encryption.

    Challenge: Try computing different operations on encrypted values!
    - Addition of encrypted values
    - Multiplication of encrypted value by a plaintext constant
    - More complex expressions
    """
    # Setup communication
    pool_alice, pool_bob, pool_charlie = await setup_three_pools()

    async def alice() -> None:
        print("\n=== ALICE ===")

        # Setup Paillier encryption scheme
        paillier: Paillier = Paillier.from_security_parameter(
            key_length=512  # WARNING: This is NOT secure! Only for demo purposes.
        )

        # Share the public key with other parties
        await pool_alice.send("bob", paillier)
        await pool_alice.send("charlie", paillier)

        # YOUR CODE HERE: Set Alice's secret value
        alice_value = 10  # Try changing this!

        # Encrypt Alice's value
        enc_alice = paillier.encrypt(alice_value)
        print(f"Alice's encrypted value: {alice_value}")

        # Send encrypted value to Bob
        await pool_alice.send("bob", enc_alice, msg_id="alice_value")

        # YOUR CODE HERE: Receive results and decrypt them
        # Hint: Use pool_alice.recv() to receive messages
        # Hint: Use paillier.decrypt() to decrypt ciphertexts
        # Example:
        # enc_result: PaillierCiphertext = await pool_alice.recv("bob", msg_id="result")
        # result = paillier.decrypt(enc_result)
        # print(f"Decrypted result: {result}")

    async def bob() -> None:
        print("\n=== BOB ===")

        # Receive the public key from Alice
        paillier: Paillier = await pool_bob.recv("alice")

        # YOUR CODE HERE: Set Bob's secret value
        bob_value = 20  # Try changing this!
        print(f"Bob's value: {bob_value}")

        # Receive Alice's encrypted value
        enc_alice: PaillierCiphertext = await pool_bob.recv("alice", msg_id="alice_value")

        # YOUR CODE HERE: Perform computations on encrypted data
        # Hint: You can add encrypted values: enc_a + enc_b
        # Hint: You can multiply by plaintext: enc_a * 5
        # Hint: You can encrypt Bob's value: paillier.encrypt(bob_value)
        # Example:
        # enc_bob = paillier.encrypt(bob_value)
        # enc_sum = enc_alice + enc_bob
        # await pool_bob.send("alice", enc_sum, msg_id="result")

    async def charlie() -> None:
        print("\n=== CHARLIE ===")

        # Receive the public key from Alice
        paillier: Paillier = await pool_charlie.recv("alice")

        # YOUR CODE HERE: Charlie can also participate!
        # What computations can Charlie perform?

    # Run all parties concurrently
    await asyncio.gather(alice(), bob(), charlie())

    # Cleanup
    await pool_alice.shutdown()
    await pool_bob.shutdown()
    await pool_charlie.shutdown()


# =============================================================================
# SECRET SHARING EXPERIMENT
# =============================================================================


async def experiment_secret_sharing() -> None:
    """
    Experiment with Shamir's Secret Sharing.

    Challenge: Try computing different operations on shared secrets!
    - Addition of shared values
    - Multiplication of shared values
    - More complex expressions
    """
    # Setup communication
    pool_alice, pool_bob, pool_charlie = await setup_three_pools()

    async def alice() -> None:
        print("\n=== ALICE ===")

        # Setup Shamir's Secret Sharing
        # Parameters: (num_parties, modulus, threshold, pool)
        shamir = ShamirSecretSharingScheme(3, 65535, 1, pool_alice)

        # YOUR CODE HERE: Set Alice's secret value
        alice_value = 5  # Try changing this!
        print(f"Alice's secret: {alice_value}")

        # Share Alice's value with other parties
        alice_shared = shamir.share("alice_secret", alice_value)
        await alice_shared.send()

        # YOUR CODE HERE: Receive shares from other parties and compute
        # Hint: Use shamir.receive() to receive shared values
        # Hint: You can add shares: share_a + share_b
        # Hint: Use share.exchange() to exchange shares before reconstruction
        # Hint: Use share.reconstruct() to get the final result
        # Example:
        # bob_shared = await shamir.receive("bob", "bob_secret")
        # sum_shared = alice_shared + bob_shared
        # await sum_shared.exchange()
        # result = sum_shared.reconstruct()
        # print(f"Result: {result}")

    async def bob() -> None:
        print("\n=== BOB ===")

        # Setup Shamir's Secret Sharing
        shamir = ShamirSecretSharingScheme(3, 65535, 1, pool_bob)

        # YOUR CODE HERE: Set Bob's secret value
        bob_value = 7  # Try changing this!
        print(f"Bob's secret: {bob_value}")

        # Share Bob's value with other parties
        bob_shared = shamir.share("bob_secret", bob_value)
        await bob_shared.send()

        # YOUR CODE HERE: Receive shares from other parties and compute
        # What operations can you perform on the shared secrets?

    async def charlie() -> None:
        print("\n=== CHARLIE ===")

        # Setup Shamir's Secret Sharing
        shamir = ShamirSecretSharingScheme(3, 65535, 1, pool_charlie)

        # YOUR CODE HERE: Set Charlie's secret value
        charlie_value = 3  # Try changing this!
        print(f"Charlie's secret: {charlie_value}")

        # Share Charlie's value with other parties
        charlie_shared = shamir.share("charlie_secret", charlie_value)
        await charlie_shared.send()

        # YOUR CODE HERE: Receive shares from other parties and compute
        # How can Charlie contribute to the computation?

    # Run all parties concurrently
    await asyncio.gather(alice(), bob(), charlie())

    # Cleanup
    await pool_alice.shutdown()
    await pool_bob.shutdown()
    await pool_charlie.shutdown()


# =============================================================================
# MAIN - Choose which experiment to run!
# =============================================================================


if __name__ == "__main__":
    print("\n" + "="*70)
    print("Welcome to the MPC Workshop Sandbox!")
    print("="*70)

    # Uncomment the experiment you want to run:

    asyncio.run(experiment_homomorphic_encryption())
    # asyncio.run(experiment_secret_sharing())

    print("\n" + "="*70)
    print("Experiment complete!")
    print("="*70 + "\n")
