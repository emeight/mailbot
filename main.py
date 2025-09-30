import logging
import os
import time
from typing import List

from dotenv import load_dotenv

from src.client import GmailServiceClient
from src.utils import load_email_set, retrieve_credentials

# configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

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

# configuration
sleep_interval = 60  # seconds
max_loops = 5

for loop_count in range(max_loops):
    logger.info(f"Beginning polling cycle {loop_count + 1} of {max_loops}")

    unread_messages = service_client.fetch_unread_messages()
    logger.info(f"Detected {len(unread_messages)} unread messages.")

    for msg_obj in unread_messages:
        service_client.reply_to_message(
            msg_obj, 
            "Your message has been received.", 
            reply_all=True
        )

    # sleep after processing, but not after the last loop
    if loop_count < max_loops - 1:
        time.sleep(sleep_interval)
