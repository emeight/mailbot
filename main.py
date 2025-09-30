import os
from typing import List

from dotenv import load_dotenv

from src.client import GmailServiceClient
from src.utils import load_email_set, retrieve_credentials

# load env variables
load_dotenv()

dev_sender: str = os.getenv("DEV_SENDER")
dev_recipient: str = os.getenv("DEV_RECIPIENT")
dev_invalid: str = os.getenv("DEV_INVALID")
scopes: List[str] = [os.getenv("SCOPES")]

valid_addresses = load_email_set(os.getenv("VALID_ADDRESS_PATH"))

# build the service client
creds = retrieve_credentials(scopes)
service_client = GmailServiceClient.from_credentials(creds, valid_addresses)


try:
    resp_dict = service_client.send_message(
        dev_recipient, "Hello World!", "It's sunny outside."
    )
    print("Successfully sent test message.")
except (ValueError, RuntimeError, Exception):
    print("Failed valid recipient test.")

try:
    sent_msg = service_client.fetch_message(resp_dict["id"])
    print("Successfully fetched test message.")
except (RuntimeError, Exception):
    print("Failed fetching test.")

try:
    invalid_resp_dict = service_client.send_message(
        dev_invalid, "Something went wrong...", "This is awkward."
    )
    raise PermissionError
except PermissionError:
    print("Permission error resulted in an email to an invalid address.")
except (RuntimeError, KeyError, Exception):
    print("Successfully failed to send a message to an invalid address.")

try:
    service_client.reply_to_message(sent_msg, "Reply test.", reply_all=True)
    print("Passed reply test.")
except (ValueError, RuntimeError, Exception):
    print("Failed reply test.")
