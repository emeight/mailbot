import logging
from typing import Dict, List, Optional, Set, Tuple

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
from src.utils import validate_email_addresses

logger = logging.getLogger(__name__)


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

    def validate_address_set(self, candidates: Set[str]) -> None:
        """Validate a set of address against the instatiated `valid_addresses` attribute."""
        return validate_email_addresses(candidates, self.valid_addresses)

    def scope_to_valid_recipients(
        self, to: List[str], cc: List[str]
    ) -> Tuple[Set[str], Set[str]]:
        """Create a tuple of valid (to, cc) addresses."""
        # create valid subsets
        valid_to_set = set(to) & self.valid_addresses
        valid_cc_set = set(cc) & self.valid_addresses

        if len(valid_to_set) < 1:
            raise ValueError("No valid recipients were specified.")

        return valid_to_set, valid_cc_set

    def fetch_message(
        self, id: str, download_attachments: bool = False
    ) -> Optional[GmailMessage]:
        """Fetch a specific message from the inbox."""
        try:
            msg = fetch_message_by_id(self.service, id, download_attachments)
            logger.info(f'Successfully retrieved message with ID: "{id}"')
        except KeyError:
            msg = None
        return msg

    def fetch_unread_messages(
        self, download_attachments: bool = False
    ) -> List[GmailMessage]:
        """Fetch unread messages from the inbox."""
        msg_id_dict = fetch_unread_message_ids(self.service)
        unread_msg_ids = list(msg_id_dict.keys())

        out = []
        ignored = []
        for msg_id in unread_msg_ids:
            try:
                # attempt to fetch the message
                sender_addr = fetch_sender_email(self.service, msg_id)
                self.validate_address_set({sender_addr})
            except ValueError:
                # invalid sender, do not fetch
                ignored.append(sender_addr)
                continue

            # if the sender was valid, fetch and append the message
            out.append(self.fetch_message(msg_id, download_attachments))

        logger.info(f"Ignored {len(ignored)} messages from the following senders: {set(ignored)}")

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
        self.validate_address_set(recipients)

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

        # this will raise an error if impossible to scope a response
        valid_to, valid_cc = self.scope_to_valid_recipients(original.to, original.cc)
        original.to = list(valid_to)
        original.cc = list(valid_cc)

        return reply_to_existing_message(
            self.service,
            original=original,
            body_text=body_text,
            reply_all=reply_all,
            body_html=body_html,
            attachment_paths=attachment_paths,
        )
