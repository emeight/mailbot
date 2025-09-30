import json
import os.path

from email.utils import getaddresses
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from typing import List, Set

from src.schemas.message import GmailMessage


def retrieve_credentials(scopes: List[str]) -> Credentials:
    """Retrieve credenentials by authorizing the application based on permission scopes.

    Parameters
    ----------
    scopes : List[str]
        List of google permission scopes.

    Returns
    -------
    creds : Credentials
        Google auth credentials.

    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", scopes)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", scopes
            )
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds


def load_email_set(path: str) -> Set[str]:
    # load list -> set; empty file defaults to empty set
    def _norm(email: str) -> str:
        # lowercase + trim; add more normalization if you need
        return email.strip().lower()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return { _norm(e) for e in data }
    except FileNotFoundError:
        return set()


def get_all_recipients(message: GmailMessage) -> Set[str]:
    """Get all unique recipient email addresses (to + from_ + cc)."""
    from_addr = getaddresses([message.from_]) if message.from_ else []
    to_list = getaddresses([message.to]) if message.to else []
    cc_list = getaddresses([message.cc]) if message.cc else []
    
    # extract just the email addresses (second element of each tuple)
    recipients = {email for _, email in from_addr + to_list + cc_list if email}
    
    return recipients


def validate_email_addresses(candidates: Set[str], valid_set: Set[str]) -> None:
    """Ensure all email addresses are part of the valid set."""
    invalid = candidates - valid_set
    if invalid:
        raise ValueError(
            f"Invalid email address(es): {', '.join(sorted(invalid))}"
        )


def validate_message_recipients(message: GmailMessage, valid_set: Set[str]) -> None:
    """Validate all possible recipients of a message object."""
    recipients = get_all_recipients(message)
    try:
        validate_email_addresses(recipients, valid_set)
    except ValueError as e:
        raise ValueError(
            f"Message {message.message_id} has invalid recipients: {e}"
        ) from e
