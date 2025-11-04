"""
Generic template for secret sharing
"""

# Explicit re-export of all functionalities, such that they can be imported properly. Following
# https://www.python.org/dev/peps/pep-0484/#stub-files and
# https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport

from tno.mpc.secret_sharing.templates.exceptions import NoCommunicationError as NoCommunicationError
from tno.mpc.secret_sharing.templates.linear import (
    LinearSecretSharingScheme as LinearSecretSharingScheme,
)
from tno.mpc.secret_sharing.templates.base import (
    SecretSharingScheme as SecretSharingScheme,
)
from tno.mpc.secret_sharing.templates.base import SecureNumber as SecureNumber

__version__ = "0.2.0"
