"""
Module implementing the additive secret sharing scheme
"""

# Explicit re-export of all functionalities, such that they can be imported properly. Following
# https://www.python.org/dev/peps/pep-0484/#stub-files and
# https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport

from tno.mpc.secret_sharing.additive.additive import (
    AdditiveSecretSharingScheme as AdditiveSecretSharingScheme,
)

__version__ = "0.1.0"
