import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from typing import List


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


def validate_email_address(candidate: str, valid_addresses: List[str]) -> bool:
    """Ensure an address is validated before interaction.

    Parameters
    -----------
    candidate : str
        Address to check for.

    valid_addresses : List[str]
        List of valid addresses.
    
    Returns
    -------
    bool
        Whether or not the address is approved for interaction.

    """
    return candidate in valid_addresses
