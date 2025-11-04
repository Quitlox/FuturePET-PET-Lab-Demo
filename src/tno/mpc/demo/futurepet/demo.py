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


async def setup_pools() -> tuple[Pool, Pool]:
    # Create Pool and Communicator for Alice
    comm_alice: Communicator = HttpCommunicator(addr="localhost", port=8100)
    pool_alice = Pool("alice", comm_alice)

    # Create Pool and Communicator for Bob
    comm_bob: Communicator = HttpCommunicator(addr="localhost", port=8101)
    pool_bob = Pool("bob", comm_bob)

    # Add a connection from Alice to Bob
    pool_alice.add_client(name="bob", connection=HttpConnection(addr="localhost", port=8101))
    # Add a connection from Bob to Alice
    pool_bob.add_client(name="alice", connection=HttpConnection(addr="localhost", port=8100))

    # Initialize
    await pool_alice.initialize()
    await pool_bob.initialize()

    return pool_alice, pool_bob


async def demo_communication() -> None:
    # Setup
    pool_alice, pool_bob = await setup_pools()

    await pool_alice.send("bob", "hello world!")
    message: str = await pool_bob.recv("alice")
    print(f"Bob received '{message}' from Alice")

    # Shutdown
    await pool_alice.shutdown()
    await pool_bob.shutdown()


async def demo_homomorphic_encryption() -> None:
    # Setup communication
    pool_alice, pool_bob = await setup_pools()

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


if __name__ == "__main__":
    # asyncio.run(demo_communication())
    asyncio.run(demo_homomorphic_encryption())
