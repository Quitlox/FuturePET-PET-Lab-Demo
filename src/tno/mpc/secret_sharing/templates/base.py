"""
Generic secret sharing scheme functionality.
"""

from __future__ import annotations

import logging
import sys
from abc import ABC, abstractmethod
from functools import cached_property
from typing import TYPE_CHECKING, Any, Generic, cast

from tno.mpc.secret_sharing.templates.exceptions import NoCommunicationError
from tno.mpc.secret_sharing.templates.utils import (
    RawSecretTypeT,
    SecretTypeT,
    ShareTypeT,
)

COMMUNICATION_INSTALLED = False
try:
    from tno.mpc.communication import Pool

    COMMUNICATION_INSTALLED = True
except ImportError:
    pass

if sys.version_info < (3, 12):
    from typing_extensions import Self
else:
    from typing import Self

if TYPE_CHECKING:
    from tno.mpc.communication import Pool

logger = logging.getLogger(__name__)


class SecretSharingScheme(ABC, Generic[SecretTypeT, RawSecretTypeT, ShareTypeT]):
    """
    Abstract base class for secret sharing schemes.
    """

    def __init__(self, n: int, pool: Pool | None = None) -> None:
        """
        Construct a new Secret Sharing scheme.

        :param n: the number of parties participating in the scheme
        :param pool: the pool to use for communication. It is assumed that all
            parties in the pool partake in the secret sharing scheme
        """
        if n <= 0:
            raise ValueError("The number of parties must be positive.")
        if pool is not None and not COMMUNICATION_INSTALLED:
            raise ImportError(
                "The communication library is not installed. Please install the "
                "communication library to use communication in the secret sharing library. "
                "See the installation guide in this repository's README."
            )

        self._n = n
        self._pool = pool

    @property
    def nr_parties(self) -> int:
        """
        Return the number of parties participating in the scheme.

        :return: the number of parties participating in the scheme
        """
        return self._n

    @property
    def pool(self) -> Pool:
        """
        Return the pool associated to this secret sharing scheme.

        The pool is used to communicate with the other parties, when shares
        need to be sent or received. It is assumed that all parties in the pool
        participate in the secret sharing protocol.

        Note that to use communication, the secret sharing scheme must be
        installed with the optional 'communication' dependency group.

        :raise NoCommunicationError: if the scheme was not properly initialized
            for communication
        :return: the pool associated to this secret sharing scheme
        """
        if self._pool is None:
            raise NoCommunicationError("Field `self.pool` is unset.")
        return self._pool

    def has_communication(self) -> bool:
        """
        Return whether the scheme is setup for communication.

        A secret sharing scheme can be used without `tno.mpc.communication` for
        just the secret sharing functionality, i.e. creating and reconstructing
        shares. To use computation and communication, the user must setup the
        scheme with a `Pool`.

        :return: whether the scheme is setup for communication
        """
        return self._pool is not None

    @cached_property
    def all_party_names(self) -> list[str]:
        """
        Return a list of all party names in the pool, including this party's
        name.

        The party names are sorted alphabetically, to ensure a consistent
        ordering. This is required by schemes such as Shamir's secret sharing
        scheme.

        :raise ValueError: if the scheme is not configured for communication
        :return: list of all party names in the pool
        """
        if not self.has_communication():
            raise ValueError(
                "This secret sharing scheme is not configured for communication."
            )
        return sorted([self.pool.name, *(self.pool.clients)])

    @cached_property
    def mapping(self) -> dict[str, int]:
        """
        Return a mapping from party names to indices.

        :return: mapping from party names to indices
        """
        return {name: i for i, name in enumerate(self.all_party_names)}

    @abstractmethod
    def empty_shares(self) -> list[ShareTypeT]:
        """
        Return a new list of shares.

        :return: a new list of shares
        """

    @abstractmethod
    def _share_secret(self, secret: RawSecretTypeT) -> list[ShareTypeT]:
        """
        Secret share an encoded (raw) value.

        This method should be implemented by any SecretSharingScheme
        subclass. The method should implement the sharing mechanism of the
        scheme.

        :param secret: the encoded (raw) value to secret share
        :return: the collection of shares that represent the secret
        """

    def get_share(self, shares: list[ShareTypeT], owner: str | int) -> ShareTypeT:
        """
        Return the share(s) belonging to the given party.

        The default implementation assumes that the i'th share belongs to the
        i'th party. This is not generally true for all secret sharing schemes
        (counter-example: replicated secret sharing).

        :param owner: the name or index of the party
        :param shares: the shares of the secret
        :return: the share(s) belonging to the given party
        """
        if isinstance(owner, int) and not (0 <= owner < self.nr_parties):
            raise IndexError(
                f"Owner index {owner} is out of bounds. "
                f"Valid range is [0, {self.nr_parties}>."
            )
        return shares[owner if isinstance(owner, int) else self.mapping[owner]]

    def get_local_share(self, shares: list[ShareTypeT]) -> ShareTypeT:
        """
        Return the share(s) belonging to the local party.

        The default implementation assumes that the i'th share belongs to the
        i'th party. This is not generally true for all secret sharing schemes
        (counter-example: replicated secret sharing).

        :param shares: the shares of the secret
        :return: the share(s) belonging to the local party
        """
        if not self.has_communication():
            raise NoCommunicationError(
                "Cannot automatically determine which share belongs to the "
                "local party without `pool.name`."
            )
        return shares[self.mapping[self.pool.name]]

    def set_share(
        self, shares: list[ShareTypeT], owner: str | int, share: ShareTypeT
    ) -> None:
        """
        Set the share(s) belonging to the given party.

        The default implementation assumes that the i'th share belongs to the
        i'th party. This is not generally true for all secret sharing schemes
        (counter-example: replicated secret sharing).

        :param owner: the name or index of the party
        :param shares: the shares of the secret
        :param share: the share(s) belonging to the given party
        """
        if isinstance(owner, int) and not (0 <= owner < self.nr_parties):
            raise IndexError(
                f"Owner index {owner} is out of bounds. "
                f"Valid range is [0, {self.nr_parties}>."
            )
        shares[owner if isinstance(owner, int) else self.mapping[owner]] = share

    def share(
        self,
        name: str,
        secret: SecretTypeT | RawSecretTypeT,
        apply_encoding: bool = True,
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Secret share a secret.

        This method encodes the secret if applicable, and then applies the
        `share` algorithm of this secret sharing scheme, implemented in
        `_share_secret`. The result is a `SecureNumber` object, which represent
        the shared secret.

        :param name: the name of the secret
        :param secret: secret to be shared
        :param apply_encoding: whether to apply the encoding of the scheme to
            the secret before sharing
        :return: sharing of the secret
        """
        secret_to_be_shared = self.apply_encoding(secret, apply_encoding)
        return SecureNumber(name, self, self._share_secret(secret_to_be_shared))

    def apply_encoding(
        self, secret: SecretTypeT | RawSecretTypeT, apply_encoding: bool = True
    ) -> RawSecretTypeT:
        """
        Apply the encoding of the scheme to the secret.

        :param secret: the secret to be encoded
        :param apply_encoding: whether to apply the encoding of the scheme
        :return: the encoded secret
        """
        return (
            self.encode(cast(SecretTypeT, secret))
            if apply_encoding
            else cast(RawSecretTypeT, secret)
        )

    async def share_and_send(
        self,
        name: str,
        secret: SecretTypeT | RawSecretTypeT,
        apply_encoding: bool = True,
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Share a secret and distribute the shares to all parties.

        This is a convenience method that calls `SecretSharingScheme.share` and
        then `SecretSharingScheme.send`.

        :param name: the name of the secret
        :param secret: secret to be shared
        :param apply_encoding: whether to apply the encoding of the scheme to
            the secret before sharing.
        :return: sharing of the secret
        """
        shared_value = self.share(name, secret, apply_encoding=apply_encoding)
        await shared_value.send()
        return shared_value

    async def share_and_send_each(
        self, name: str, secret: SecretTypeT
    ) -> tuple[SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT], ...]:
        """
        Let each party share a secret and distribute the shares to all parties.

        This is a convenience method for when a secret value needs to be symmetrically
        input by all parties.

        :param name: the name of the secret
        :param secret: secret to be shared by this party
        :return: a list of the shared secrets
        """
        secret_local = self.share(f"{name}_{self.pool.name}", secret)

        msg_id = f"{self.__class__.__name__}_share_each_{name}"
        for party in self.pool.clients:
            message = secret_local.get_share(party)
            await self.pool.send(party, message, msg_id=msg_id)

        messages = await self.pool.recv_all(msg_id=msg_id)
        secrets = [secret_local] + [
            SecureNumber.from_share(f"{name}_{party}", share, self, party)
            for party, share in messages
        ]

        return tuple(sorted((i for i in secrets), key=lambda x: x.name))

    async def receive(
        self, party_name: str, secret_name: str
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Receive a shared value from another party.

        Use this method to receive the share(s) corresponding to a secret from
        another party. Note that the secret must be known under the same name
        by both parties for the communication to succeed,
        i.e. `SecretSharingScheme.send` and `SecretSharingScheme.receive`
        should have the same value for the parameter `secret_name`.

        :param party_name: the name of the party to receive the shared value from
        :param secret_name: the name of the secret to receive
        :raise ValueError: if the party is not in the pool
        :return: the received shared value
        """
        if party_name not in self.pool.clients:
            raise ValueError(f"Party {party_name} is not in the pool.")

        msg_id = f"{self.__class__.__name__}_send/recv_{secret_name}"
        value = await self.pool.recv(party_name, msg_id=msg_id)

        return SecureNumber.from_share(secret_name, value, self)

    @abstractmethod
    def encode(self, value: SecretTypeT) -> RawSecretTypeT:
        """
        Encode a supported value using the specified scheme.

        :param value: value to be encoded
        :return: the encoded value
        """

    @abstractmethod
    def decode(self, encoded_value: RawSecretTypeT) -> SecretTypeT:
        """
        Decode an encoded value.

        :param encoded_value: encoded value to be decoded
        :return: the decoded value
        """

    async def add(
        self,
        value1: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT],
        value2: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT] | RawSecretTypeT,
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Add one secret with another secret or a public value.

        :param value1: shares representing a secret to be added
        :param value2: shares representing a secret to be added, or a public
            value to be added to the secret
        :return: the shares representing the sum of the two values
        """
        raise NotImplementedError()

    async def neg(
        self, value1: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Negate this secret.

        :param value1: shares representing a secret to be negated
        :return: the shares representing the negative of the value
        """
        raise NotImplementedError()

    async def sub(
        self,
        value1: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT],
        value2: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT] | RawSecretTypeT,
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Subtract another secret or a public value from this secret.

        :param value1: shares representing a secret to be subtracted from
        :param value2: shares representing a secret to be subtracted, or a public
            value to be subtracted from the secret
        :return: the shares representing the difference of the two values
        """
        raise NotImplementedError()

    async def mul(
        self,
        value1: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT],
        value2: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT] | RawSecretTypeT,
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Multiply one secret with another secret or a public value.

        :param value1: shares representing a secret to be multiplied
        :param value2: shares representing a secret to be multiplied, or a public
            value to be multiplied to the secret
        :return: the shares representing the product of the two values
        """
        raise NotImplementedError()

    def _add_sync(
        self,
        value1: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT],
        value2: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT] | RawSecretTypeT,
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Synchronously add one secret with another secret or a public value.
        This only works for linear secret sharing schemes,
        i.e. schemes that support linear operations without additional communication.

        :param value1: shares representing a secret to be added
        :param value2: shares representing a secret to be added, or a public
            value to be added to the secret
        :return: the shares representing the sum of the two values
        """
        raise NotImplementedError()

    def _mul_sync(
        self,
        value1: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT],
        value2: RawSecretTypeT,
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Synchronously multiply one secret with a public value.
        This only works for linear secret sharing schemes,
        i.e. schemes that support linear operations without additional communication.

        :param value1: shares representing a secret to be multiplied
        :param value2: shares representing a public value to be multiplied with the secret
        :return: the shares representing the product of the two values
        """
        raise NotImplementedError()

    def _reconstruct(
        self: Self,
        shares: list[ShareTypeT],
        apply_encoding: bool = True,
        other_parties: set[str] | None = None,
    ) -> SecretTypeT:
        """
        Reconstruct the underlying secret from the shares.

        :param shares: the shares of the secret
        :param apply_encoding: whether to apply the encoding scheme to the
            result, meaning to decode the result
        :param other_parties: the other parties that are together reconstructing the secret
        :return: the reconstructed secret, decoded if applicable
        """
        raw = self._reconstruct_raw(shares, other_parties=other_parties)
        return self.decode(raw) if apply_encoding else cast(SecretTypeT, raw)

    @abstractmethod
    def _reconstruct_raw(
        self: Self, shares: list[ShareTypeT], other_parties: set[str] | None = None
    ) -> RawSecretTypeT:
        """
        Reconstruct the underlying secret from the shares.

        This method should be used to implement the reconstruct algorithm of
        the secret sharing scheme. This method does not perform any
        communication, i.e. the shares must already be present. See
        `exchange_and_reconstruct` for a method that performs communication.

        :param shares: the shares of the secret.
        :param other_parties: the other parties that are together reconstructing the secret
        :return: the reconstructed secret
        """

    def __eq__(self, other: object) -> bool:
        """
        Check if two SecretSharingScheme objects are equal.

        Two schemes are found to be equal if their parameters are equal.

        :param other: other object to compare to.
        :return: True if equal, False otherwise.
        """
        return hash(self) == hash(other)

    def __hash__(self) -> int:
        """
        Return the hash of the object.

        :return: the hash of the object.
        """
        raise NotImplementedError()

    def __str__(self) -> str:
        return f"{self.__class__.__name__}()"

    __repr__ = __str__


class SecureNumber(Generic[SecretTypeT, RawSecretTypeT, ShareTypeT]):
    """
    Class that represents a particular secret shared using
    a SecretSharingScheme. The class uses the linked SecretSharingScheme to
    provide arithmetic functionality.

    Note that a SecureNumber is not necessarily the same as a "share". If the
    secret is known to the local party, the party may have all shares. However,
    if the secret was created by another party, or is the result of
    a calculation, the party will only have the share(s) that was created for her.

    This class is not intended to be constructed directly. Instead, use the
    `SecretSharingScheme.share` method to share a new secret. To receive shared
    secret from another party, use the `SecretSharingScheme.receive` method.
    """

    def __init__(
        self,
        name: str,
        scheme: SecretSharingScheme[SecretTypeT, RawSecretTypeT, ShareTypeT],
        shares: list[ShareTypeT] | None = None,
    ) -> None:
        """
        Construct a new SecureNumber object. For internal use only.

        To create a new SecureNumber, use the `SecretSharingScheme.share`
        (or `SecretSharingScheme.share_and_send`) method. To receive
        a SecureNumber from another party, use the `SecretSharingScheme.receive`
        method.

        :param name: the name of the secret
        :param scheme: the scheme to use for sharing
        :param shares: the shares of the secret
        """
        self._name = name
        self._scheme = scheme
        self._shares: list[ShareTypeT] = shares or []

    @property
    def scheme(self) -> SecretSharingScheme[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Return the scheme used to share the secret.

        :return: the scheme used to share the secret
        """
        return self._scheme

    @property
    def name(self) -> str:
        """
        Return the name of the secret.

        :return: the name of the secret
        """
        return self._name

    @property
    def shares(self) -> list[Any]:
        """
        Return the shares of the secret.

        :return: the shares of the secret
        """
        return self._shares

    async def validate_identifiers(self) -> None:
        """
        Validate that all parties use the same party names.

        It is important that all parties use the same party names, as the
        party names are used to map the shares to the correct party. Swapped
        shares can result in incorrect behavior.

        :raise ValueError: if there is a mismatch in party names
        """
        await self.scheme.pool.broadcast(
            self.scheme.all_party_names,
            msg_id=f"{self.__class__.__name__}_validate_identifiers",
        )
        messages = await self.scheme.pool.recv_all(
            msg_id=f"{self.__class__.__name__}_validate_identifiers"
        )

        for party, result in messages:
            if result != self.scheme.all_party_names:
                raise ValueError(
                    f"Mismatch in party names. "
                    f"This party expected {self.scheme.all_party_names}, "
                    f"but {party} returned {result}."
                )

    def reconstruct(
        self: Self, apply_encoding: bool = True, other_parties: set[str] | None = None
    ) -> SecretTypeT:
        """
        Reconstruct the underlying secret from the shares.

        This method is a wrapper around `_reconstruct_raw` that applies the
        encoding of the scheme to the result, if applicable. This method does
        not perform any communication, i.e. the shares must already be
        present. See `exchange_and_reconstruct` for a method that performs
        communication.

        :param apply_encoding: whether to apply the encoding of the scheme to
            the result
        :param other_parties: the other parties that are together reconstructing the secret
        :return: the reconstructed secret
        """
        return self.scheme._reconstruct(  # pylint: disable=[protected-access]
            self._shares, apply_encoding=apply_encoding, other_parties=other_parties
        )

    async def exchange(self: Self, other_parties: set[str] | None = None) -> None:
        """
        Exchange the shares for this secret with all other parties in the pool.

        All parties end up with all shares. Call `reconstruct` to reconstruct
        the underlying secret from the shares.

        :param other_parties: the other parties with whom the shares are exchanged
        :raise ValueError: if party does not have exactly one share
        """
        if len(self._shares) == 0:
            raise ValueError("This party has no shares for this secret.")

        other_parties = other_parties or self.scheme.pool.clients
        msg_id = f"{self.scheme.__class__.__name__}_exchange_{self.name}"
        # Send shares to all other parties
        message = self.get_share(self.scheme.pool.name)
        await self.scheme.pool.broadcast(message, msg_id=msg_id)
        # Receive shares from all other parties
        messages = await self.scheme.pool.recv_all(
            sender_names=other_parties, msg_id=msg_id
        )
        for party, share in messages:
            self.set_share(party, share)

    async def exchange_and_reconstruct(
        self: Self, apply_encoding: bool = True, other_parties: set[str] | None = None
    ) -> SecretTypeT:
        """
        Exchange shares with the other parties and reconstruct the underlying
        secret from the shares.

        :param apply_encoding: whether to apply encoding
        :param other_parties: the other parties that are together reconstructing the secret;
            if this is None, all parties are participating in the reconstruction
        :raise TypeError: if `other_parties` is supplied, but the scheme is not a threshold scheme
        :raise ValueError: if fewer parties than the threshold are supplied.
        :return: the reconstructed secret
        """
        await self.exchange(other_parties=other_parties)
        return self.reconstruct(
            apply_encoding=apply_encoding, other_parties=other_parties
        )

    async def send(self: Self) -> None:
        """
        Distribute the shares for this secret to all parties in the pool.

        Should be called after `SecretSharingScheme.share`. Other parties must
        call `SecretSharingScheme.receive` to receive their share(s).
        """
        for party in self.scheme.pool.clients:
            msg_id = f"{self.scheme.__class__.__name__}_send/recv_{self.name}"
            message = self.get_share(party)
            await self.scheme.pool.send(party, message, msg_id=msg_id)

    def get_share(self, party: str) -> ShareTypeT:
        """
        Return the share(s) belonging to the given party.

        :param party: the name of the party
        :return: the share(s) belonging to the given party
        """
        return self.scheme.get_share(self._shares, party)

    @property
    def get_local_share(self) -> ShareTypeT:
        """
        Return the share(s) belonging to the local party.

        :return: the share(s) belonging to the local party
        """
        return self.scheme.get_local_share(self._shares)

    def set_share(self, party: str, share: ShareTypeT) -> None:
        """
        Set the share(s) belonging to the given party.

        :param party: the name of the party
        :param share: the share(s) belonging to the given party
        """
        self._scheme.set_share(self._shares, party, share)

    @classmethod
    def from_share(
        cls,
        secret_name: str,
        share: ShareTypeT,
        scheme: SecretSharingScheme[Any, Any, Any],
        owner: str | int | None = None,
    ) -> Self:
        """
        Construct a SecureNumber object from a single share.

        This method is intended to be used to convert a sole `ShareTypeT` into
        a `SecureNumber` object, to make computation on the secret that the
        share represents possible.

        The `owner` parameter is optional. By default, the share given is
        assumed to belong to the local party.

        :param secret_name: the name of the secret.
        :param share: the share of the secret belonging to this party.
        :param scheme: the scheme to which the secret belongs.
        :param owner: the name or index of the party to which the share
            belongs. Defaults to `scheme.pool.name`.
        :return: the constructed SecureNumber object.
        """
        if not owner and not scheme.has_communication():
            raise ValueError(
                "Cannot determine which index to set the share for without an "
                "explicit owner specified or a `scheme.pool`."
            )

        shares = scheme.empty_shares()
        scheme.set_share(owner=owner or scheme.pool.name, share=share, shares=shares)
        return cls(name=secret_name, scheme=scheme, shares=shares)

    def __add__(
        self,
        other: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT] | RawSecretTypeT,
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Overload the addition operator. This calls the _add_sync function.

        :param other: shares representing a secret to be added, or a public
            value to be added to the secret
        :return: shares representing the sum of the two values
        """
        return self.scheme._add_sync(self, other)

    __radd__ = __add__

    def __mul__(
        self, other: RawSecretTypeT
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Overload the multiplication operator. This calls the _mul_sync function.

        :param other: A public value to be multiplied with the secret
        :return: shares representing the product of the two values
        """
        return self.scheme._mul_sync(self, other)

    __rmul__ = __mul__

    def __neg__(self) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Overload the negation operator. This calls the _mul_sync function.

        :return: shares representing the negation of the value
        """
        return self * cast(RawSecretTypeT, -1)

    def __sub__(
        self,
        other: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT] | RawSecretTypeT,
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Overload the subtraction operator. This calls the _add_sync and _mul_sync function.

        :param other: shares representing a secret to be subtracted, or a public
            value to be subtracted from the secret
        :return: shares representing the difference of the two values
        """
        return self + (-other)

    def __rsub__(
        self,
        other: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT] | RawSecretTypeT,
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Overload the mirrored subtraction operator. This calls the _add_sync and _mul_sync function.

        Note that we need to call SecureNumber.__neg__(self) here in order to
        negate the secret.

        :param other: shares representing a secret or a public
            value from which the secret is subtracted
        :return: shares representing the difference of the two values
        """
        return other + (-self)

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"

    __repr__ = __str__
