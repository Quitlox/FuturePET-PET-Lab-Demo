class NoCommunicationError(Exception):
    """
    Exception raised when communication is required but not properly set up.
    """

    def __init__(self, specific_reason: str) -> None:
        """
        Initialize the exception with a specific reason and general setup tip.

        :param specific_reason: The specific reason why communication is needed.
        """
        general_tip = (
            "To use communication, use " "`SecretSharingScheme(..., pool=...)`"
        )
        super().__init__(f"{specific_reason} {general_tip}")
