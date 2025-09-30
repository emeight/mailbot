from typing import List, Optional

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import Resource, build

from src.impl.message import fetch_message_by_id, fetch_unread_message_ids
from src.schemas.message import GmailMessage


class GmailServiceClient:
    """Gmail resource wrapper.

    Attributes
    ----------
    service : Resource
        Discovery-built Gmail service (build("gmail","v1",credentials=...)).

    Methods
    -------


    """

    service: Resource

    def __init__(self, service: Resource) -> None:
        self.service = service

    @classmethod
    def from_credentials(cls, creds: Credentials) -> "GmailServiceClient":
        """Build a GmailServiceClient instance from a Credentials object."""
        service = build("gmail", "v1", credentials=creds)
        return cls(service)

    def fetch_unread_messages(self) -> List[str]:
        """Fetch unread messages from the inbox."""
        msg_id_dict = fetch_unread_message_ids(self.service)
        return list(msg_id_dict.keys())

    def fetch_message(
        self, id: str, download_attachments: bool = False
    ) -> Optional[GmailMessage]:
        """Fetch all messages from the inbox.

        Parameters
        ----------
        id : str
            Unique message identifier.

        download_attachments : bool
            Whether or not to download message attachments.
            Defaults to False (only retrieves metadata).

        Returns
        -------
        Optional[GmailMessage]
            Structured messaged object corresponding to `id` if it exists, otherwise None.

        """
        try:
            msg = fetch_message_by_id(self.service, id, download_attachments)
        except KeyError:
            msg = None
        return msg
