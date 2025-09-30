from typing import Dict, List, Optional, Set

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import Resource, build

from src.impl.message import (
    fetch_message_by_id,
    fetch_sender_email,
    fetch_unread_message_ids,
    reply_to_existing_message,
    send_new_message,
)
from src.schemas.message import GmailMessage
from src.utils import validate_email_addresses, validate_message_recipients


class GmailServiceClient:
    """Gmail resource wrapper.

    Validation is baked in at this level to ensure that the client is secure.

    Attributes
    ----------
    service : Resource
        Discovery-built Gmail service (build("gmail","v1",credentials=...)).

    valid_addresses : Set[str]
        Valid email addresses who can engage with this client.

    """

    service: Resource
    valid_addresses: Set[str]

    def __init__(self, service: Resource, valid_addresses: Set[str]) -> None:
        self.service = service
        self.valid_addresses = valid_addresses

    @classmethod
    def from_credentials(
        cls, creds: Credentials, valid_addresses: Set[str]
    ) -> "GmailServiceClient":
        """Build a GmailServiceClient instance from a Credentials object."""
        service = build("gmail", "v1", credentials=creds)
        return cls(service, valid_addresses)

    def fetch_message(
        self, id: str, download_attachments: bool = False
    ) -> Optional[GmailMessage]:
        """Fetch a specific message from the inbox."""
        try:
            msg = fetch_message_by_id(self.service, id, download_attachments)
        except KeyError:
            msg = None
        return msg

    def fetch_unread_messages(self, download_attachments: bool = False) -> List[GmailMessage]:
        """Fetch unread messages from the inbox."""
        msg_id_dict = fetch_unread_message_ids(self.service)
        unread_msg_ids = list(msg_id_dict.keys())

        out = []
        for msg_id in unread_msg_ids:
            try:
                # attempt to fetch the message
                sender_addr = fetch_sender_email(self.service, msg_id)
                validate_email_addresses({sender_addr}, self.valid_addresses)
            except ValueError:
                # invalid sender, do not fetch
                continue

            # if the sender was valid, fetch and append the message
            out.append(self.fetch_message(msg_id, download_attachments))

        return out

    def send_message(
        self,
        to: List[str],
        subject: str,
        body_text: str,
        *,
        cc: Optional[List[str]] = None,
        attachment_paths: Optional[List[str]] = None,
        body_html: Optional[str] = None,
        reply_to: Optional[str] = None,
    ) -> Dict[str, str]:
        """Send an email to the specified recipient."""
        # recipient validation
        recipients = set(to)
        if cc:
            recipients.update(cc)
        validate_email_addresses(recipients, self.valid_addresses)

        return send_new_message(
            self.service,
            to=to,
            subject=subject,
            body_text=body_text,
            cc=cc,
            attachment_paths=attachment_paths,
            body_html=body_html,
            reply_to=reply_to,
        )

    def reply_to_message(
        self,
        original: GmailMessage,
        body_text: str,
        *,
        reply_all: bool = False,
        body_html: Optional[str] = None,
        attachment_paths: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Reply to an existing email message."""

        if original.from_ not in self.valid_addresses:
            raise ValueError("Original sender is invalid.")

        if not set(original.to) <= self.valid_addresses:
            raise ValueError("Primary recipients are invalid.")

        try:
            # validate recipients
            validate_message_recipients(original, self.valid_addresses)
        except ValueError:
            if reply_all:
                # create a subset of valid response addresses
                original.cc = list(set(original.cc) & self.valid_addresses)
            else:
                # re-raise the error
                raise

        return reply_to_existing_message(
            self.service,
            original=original,
            body_text=body_text,
            reply_all=reply_all,
            body_html=body_html,
            attachment_paths=attachment_paths,
        )
