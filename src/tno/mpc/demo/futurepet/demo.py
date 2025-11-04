"""
Demonstration module.
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
from tno.mpc.secret_sharing.shamir import (
    ShamirSecretSharingScheme,
)


async def setup_two_pools() -> tuple[Pool, Pool]:

    async def alice():
        # Create Pool and Communicator for Alice
        comm_alice: Communicator = HttpCommunicator(addr="localhost", port=8100)
        pool_alice = Pool("alice", comm_alice)
        # Add a connection from Alice to Bob
        pool_alice.add_client(name="bob", connection=HttpConnection(addr="localhost", port=8101))
        # Initialize
        await pool_alice.initialize()
        return pool_alice

    async def bob():
        # Create Pool and Communicator for Bob
        comm_bob: Communicator = HttpCommunicator(addr="localhost", port=8101)
        pool_bob = Pool("bob", comm_bob)
        # Add a connection from Bob to Alice
        pool_bob.add_client(name="alice", connection=HttpConnection(addr="localhost", port=8100))
        # Initialize
        await pool_bob.initialize()
        return pool_bob

    return await asyncio.gather(alice(), bob())


async def setup_three_pools() -> tuple[Pool, Pool, Pool]:
    # Create Pool and Communicator for Alice
    comm_alice: Communicator = HttpCommunicator(addr="localhost", port=8100)
    pool_alice = Pool("alice", comm_alice)

    # Create Pool and Communicator for Bob
    comm_bob: Communicator = HttpCommunicator(addr="localhost", port=8101)
    pool_bob = Pool("bob", comm_bob)

    # Create Pool and Communicator for Charlie
    comm_charlie: Communicator = HttpCommunicator(addr="localhost", port=8102)
    pool_charlie = Pool("charlie", comm_charlie)

    # Add connectionts
    pool_alice.add_client(name="bob", connection=HttpConnection(addr="localhost", port=8101))
    pool_alice.add_client(name="charlie", connection=HttpConnection(addr="localhost", port=8102))
    pool_bob.add_client(name="alice", connection=HttpConnection(addr="localhost", port=8100))
    pool_bob.add_client(name="charlie", connection=HttpConnection(addr="localhost", port=8102))
    pool_charlie.add_client(name="alice", connection=HttpConnection(addr="localhost", port=8100))
    pool_charlie.add_client(name="bob", connection=HttpConnection(addr="localhost", port=8101))

    # Initialize
    await pool_alice.initialize()
    await pool_bob.initialize()
    await pool_charlie.initialize()

    return pool_alice, pool_bob, pool_charlie


async def demo_communication() -> None:
    # Setup
    pool_alice, pool_bob = await setup_two_pools()

    async def alice() -> None:
        message = "Hello World!"
        await pool_alice.send("bob", message)
        print(f"Alice sent '{message}' to Bob")

    async def bob() -> None:
        message: str = await pool_bob.recv("alice")
        print(f"Bob received '{message}' from Alice")

    await asyncio.gather(alice(), bob())

    # Shutdown
    await pool_alice.shutdown()
    await pool_bob.shutdown()


async def demo_homomorphic_encryption() -> None:
    # Setup communication
    pool_alice, pool_bob = await setup_two_pools()

    # Demo
    async def alice() -> None:
        # Setup scheme
        paillier: Paillier = Paillier.from_security_parameter(key_length=512)  # WARNING: key_length not secure
        await pool_alice.send(recipient_name="bob", message=paillier)

        x = 4
        # Perform secure computation
        enc_x = paillier.encrypt(x)
        await pool_alice.send(recipient_name="bob", message=enc_x, msg_id="x")
        enc_z: PaillierCiphertext = await pool_alice.recv(sender_name="bob", msg_id="z")
        plain_z = paillier.decrypt(enc_z)

        print(f"z = x + y = {plain_z}")

    async def bob() -> None:
        # Setup scheme
        paillier: Paillier = await pool_bob.recv(sender_name="alice")

        y = 5
        # Perform secure computation
        enc_x: PaillierCiphertext = await pool_bob.recv(sender_name="alice", msg_id="x")
        enc_y = paillier.encrypt(y)

        enc_z = enc_x + enc_y
        await pool_bob.send("alice", enc_z, msg_id="z")

    # Shutdown
    await asyncio.gather(*[alice(), bob()])
    await asyncio.gather(*[pool_alice.shutdown(), pool_bob.shutdown()])


async def demo_secret_sharing() -> None:
    # Setup communication
    pool_alice, pool_bob, pool_charlie = await setup_three_pools()

    # Demo
    async def alice() -> None:
        shamir = ShamirSecretSharingScheme(3, 65535, 1, pool_alice)
        x_shared = shamir.share("x", 1)
        await x_shared.send()
        y_shared = await shamir.receive("bob", "y")
        z_shared = await shamir.receive("charlie", "z")
        sum_shared = x_shared + y_shared + z_shared
        await sum_shared.exchange()
        print(sum_shared.reconstruct())

    async def bob() -> None:
        shamir = ShamirSecretSharingScheme(3, 65535, 1, pool_bob)
        y_shared = shamir.share("y", 2)
        await y_shared.send()
        x_shared = await shamir.receive("alice", "x")
        z_shared = await shamir.receive("charlie", "z")
        sum_shared = x_shared + y_shared + z_shared
        await sum_shared.exchange()
        print(sum_shared.reconstruct())

    async def charlie() -> None:
        shamir = ShamirSecretSharingScheme(3, 65535, 1, pool_charlie)
        z_shared = shamir.share("z", 3)
        await z_shared.send()
        x_shared = await shamir.receive("alice", "x")
        y_shared = await shamir.receive("bob", "y")
        sum_shared = x_shared + y_shared + z_shared
        await sum_shared.exchange()
        print(sum_shared.reconstruct())

    # Shutdown
    await asyncio.gather(*[alice(), bob(), charlie()])
    await asyncio.gather(*[pool_alice.shutdown(), pool_bob.shutdown(), pool_charlie.shutdown()])


if __name__ == "__main__":
    # asyncio.run(demo_communication())
    # asyncio.run(demo_homomorphic_encryption())
    asyncio.run(demo_secret_sharing())
