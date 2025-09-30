import json
import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from typing import List, Set


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


def validate_email_address(candidate: str, valid_set: Set) -> bool:
    """Ensure an email address is part of the valid set."""
    # O(1) lookup time
    return candidate in valid_set
