"""
Generic linear secret sharing scheme.

This scheme adapts the SecretSharingScheme class, and implements direct
synchronous linear operations, i.e. addition and scalar multiplication, from
which negation and subtraction are defined indirectly.
"""

from __future__ import annotations

import logging
from abc import abstractmethod
from typing import TYPE_CHECKING, Generic

from tno.mpc.secret_sharing.templates.base import (
    SecretSharingScheme,
    SecureNumber,
)
from tno.mpc.secret_sharing.templates.utils import (
    RawSecretTypeT,
    SecretTypeT,
    ShareTypeT,
)

if TYPE_CHECKING:
    from tno.mpc.communication import Pool

logger = logging.getLogger(__name__)


class LinearSecretSharingScheme(
    SecretSharingScheme[SecretTypeT, RawSecretTypeT, ShareTypeT],
    Generic[SecretTypeT, RawSecretTypeT, ShareTypeT],
):
    """
    Base class for linear secret sharing schemes.

    These support linear operations (addition, subtraction, negation, scalar multiplication)
    directly and synchronously without needing additional communication.
    This means this class can overload the +, - and * operators with synchronous functions.
    """

    def __init__(self, n: int, pool: Pool | None = None) -> None:
        SecretSharingScheme.__init__(self, n=n, pool=pool)

    @abstractmethod
    def _add_encoded(self, value1: ShareTypeT, value2: ShareTypeT) -> ShareTypeT:
        """
        Add one secret with another secret value.

        This method should be used to implement the addition
        algorithm of the secret sharing scheme.

        :param value1: share representing a secret to be added
        :param value2: share representing a secret to be added
        :return: the shares representing the sum of the two values
        """

    @abstractmethod
    def _scalar_add_encoded(
        self, value1: ShareTypeT, value2: RawSecretTypeT
    ) -> ShareTypeT:
        """
        Add one secret with another public value.

        This method should be used to implement the scalar addition
        algorithm of the secret sharing scheme.

        :param value1: share representing a secret to be added
        :param value2: a public value to be added to the secret
        :return: the shares representing the sum of the two values
        """

    def _add_sync(
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
        index = self.mapping[self.pool.name]
        if isinstance(value2, SecureNumber):
            added_value = self._add_encoded(
                value1.get_local_share, value2.get_local_share
            )
            return SecureNumber.from_share(
                f"{value1.name}+{value2.name}",
                added_value,
                self,
            )

        added_value = self._scalar_add_encoded(value1.get_local_share, value2)
        return SecureNumber.from_share(
            f"{value1.name}+{value2}",
            added_value,
            self,
        )

    @abstractmethod
    async def _mul_encoded(
        self, value1: ShareTypeT, value2: ShareTypeT, resharing_id: str | None = None
    ) -> ShareTypeT:
        """
        Multiply one secret with another secret value.

        This method should be used to implement the multiplication
        algorithm of the secret sharing scheme.

        :param value1: share representing a secret to be multiplied
        :param value2: share representing a secret to be multiplied
        :param resharing_id: string to identify the multiplication
            when resharing values and avoid possible race conditions
        :return: the shares representing the product of the two values
        """

    @abstractmethod
    def _scalar_mul_encoded(
        self, value1: ShareTypeT, value2: RawSecretTypeT
    ) -> ShareTypeT:
        """
        Multiply one secret with another public value.

        This method should be used to implement the scalar multiplication
        algorithm of the secret sharing scheme.

        :param value1: share representing a secret to be multiplied
        :param value2: a public value to be multiplied to the secret
        :return: the shares representing the product of the two values
        """

    def _mul_sync(
        self,
        value1: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT],
        value2: RawSecretTypeT,
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Multiply one secret with another public value.

        :param value1: shares representing a secret to be multiplied
        :param value2: shares representing a public value to be multiplied with the secret
        :raise TypeError: if the wrong multiplication method is called
        :return: the shares representing the product of the two values
        """
        index = self.mapping[self.pool.name]
        if isinstance(value2, SecureNumber):
            raise TypeError(
                "Multiplication of two secrets is not a linear operation "
                "and requires additional communication. "
                "For this use `scheme.mul(x, y)` rather than `x * y`"
            )

        multiplied_value = self._scalar_mul_encoded(value1.get_local_share, value2)
        return SecureNumber.from_share(
            f"({value1.name})*{value2}",
            multiplied_value,
            self,
        )

    async def mul(
        self,
        value1: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT],
        value2: SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT] | RawSecretTypeT,
    ) -> SecureNumber[SecretTypeT, RawSecretTypeT, ShareTypeT]:
        """
        Asynchronously multiply two secrets with each other.

        :param value1: shares representing a secret to be multiplied
        :param value2: shares representing a secret to be multiplied
        :raise TypeError: if the wrong multiplication method is called
        :return: shares representing the product of the two values
        """
        if not (isinstance(value1, SecureNumber) and isinstance(value2, SecureNumber)):
            raise TypeError(
                "Multiplication with a constant is a linear operation "
                "and does not require additional communication. "
                "For this use x * y rather than scheme.mul(x, y)"
            )

        multiplied_value = await self._mul_encoded(
            value1.get_local_share,
            value2.get_local_share,
            f"({value1.name})*{value2.name}",
        )
        return SecureNumber.from_share(
            f"({value1.name})*{value2.name}",
            multiplied_value,
            self,
        )
