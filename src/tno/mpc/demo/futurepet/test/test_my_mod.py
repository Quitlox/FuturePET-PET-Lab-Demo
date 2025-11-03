"""
Tests for tno.mpc.demo.futurepet module.
"""

from tno.mpc.demo.futurepet.my_mod import is_this_module_awesome


def test_is_this_module_awesome_returns_truth() -> None:
    """
    Validates that the question is answered truthfully.
    """
    assert is_this_module_awesome()
