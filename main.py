import os

from dotenv import load_dotenv
from typing import List

from src.utils import retrieve_credentials
from src.client import GmailServiceClient


# load env variables
load_dotenv()
dev_address: str = os.getenv("DEV_ADDRESS")
scopes: List[str] = [os.getenv("SCOPES")]

# build credentials
creds = retrieve_credentials(scopes)

# instantiate the service client
service_client = GmailServiceClient.from_credentials(creds)

unread_ids = service_client.fetch_unread_messages()

msg = service_client.fetch_message(unread_ids[0])
print(msg)

# monitor inbox for emails
# only view emails from validated sources
# send back a message