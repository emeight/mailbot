import base64

from googleapiclient.discovery import Resource
from googleapiclient.errors import HttpError

from typing import Dict, List, Optional, Union

from src.schemas.message import GmailAttachment, GmailMessage


def build_headers_dict(payload_headers: List[Dict]) -> Dict[str, str]:
    """Normalize headers into a case-insensitive dict (keys as canonical names)."""
    out: Dict[str, str] = {}
    for h in payload_headers or []:
        name = (h.get("name") or "").strip()
        value = (h.get("value") or "").strip()
        if name:
            # preserve the last occurrence; Gmail may repeat some headers
            out[name] = value
    return out


def decode_b64url_to_text(b64: str) -> str:
    """Decode Gmail base64url string to utf-8 text (best-effort)."""
    raw = base64.urlsafe_b64decode(b64.encode("utf-8"))
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        # extremely rare, but we still guarantee a string
        return raw.decode("latin-1", errors="replace")


def extract_message_content(
    part: Dict,
    found: Dict[str, Optional[str]],
    attachments: List[GmailAttachment],
) -> None:
    """
    Depth-first traversal of a Gmail MIME tree to extract message content.

    This function mutates the provided `found` and `attachments` containers
    in place. It does not return a value.

    Parameters
    ----------
    part : Dict
        A Gmail API message payload or sub-part, containing headers, body,
        and optional nested `parts`.

    found : Dict[str, Optional[str]]
        A dictionary accumulator for decoded body content. Modified in place.
        Keys should include at least `"text/plain"` and `"text/html"`.

    attachments : List[GmailAttachment]
        A list accumulator for attachment metadata. Modified in place.

    """
    if not part:
        return

    mime_type = part.get("mimeType") or ""
    body = part.get("body") or {}
    filename = (part.get("filename") or "").strip()
    data = body.get("data")
    attachment_id = body.get("attachmentId")
    size = int(body.get("size") or 0)

    # treat as attachment if it has a filename or attachmentId (common Gmail behavior)
    if filename or attachment_id:
        if attachment_id:
            attachments.append(
                GmailAttachment(
                    attachment_id=attachment_id,
                    filename=filename or "(no name)",
                    mime_type=mime_type,
                    size=size,
                    data_base64=None,
                )
            )
        # Note: inline images sometimes come without filename; those won’t appear unless attachmentId exists.

    # capture body text/html
    if data and mime_type == "text/plain" and found.get("text/plain") is None:
        found["text/plain"] = decode_b64url_to_text(data)
    if data and mime_type == "text/html" and found.get("text/html") is None:
        found["text/html"] = decode_b64url_to_text(data)

    # recurse into subparts
    for child in part.get("parts") or []:
        extract_message_content(child, found, attachments)


def fetch_unread_message_ids(service: Resource) -> Dict[str, Dict[str, str]]:
    """Retrieve unread message ids.
    
    Parameters
    ----------
    service : Resource
        googleapiclient resource object.

    Returns
    -------
    Dict[str, str]
        Dictionary keyed by unread message "id", sub-dictionary contains "thread_id" attribute.

    """
    unread_map = {}
    page_token = None

    while True:
        # users.messages.list returns dictionary with "messages" (List[Dict[str, str]]), "nextPageToken" (str), and "resultSizeEstimate" (int)
        resp: Dict[str, Optional[Union[Dict[str, str], str, int]]] = service.users().messages().list(
            userId="me",
            labelIds=["INBOX"],
            q="is:unread",
            maxResults=500,
            pageToken=page_token,
        ).execute()

        for m in resp.get("messages", []):
            unread_map[m["id"]] = {"threadId": m["threadId"]}

        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    
    # returns dict of dicts keyed by message id {"id": {"threadId": "abc123"}}
    return unread_map


def fetch_message_by_id(service: Resource, id: str, download_attachments: bool = False) -> GmailMessage:
    """Query the service client for a message.

    Parameters
    ----------
    service : Resource
        googleapiclient resource object.

    id : str
        Unique message identifier.

    download_attachments : bool
        Whether or not to download message attachments.
        Defaults to False (only retrieves metadata).

    Raises
    ------
    KeyError
        If `id` is not found in the inbox.

    Returns
    -------
    GmailMessage
        Structured message object.

    """
    try:
        # query the service for a full message response
        msg: Dict[str, Optional[Union[Dict[str, str], str, int]]] = (
            service.users()
            .messages()
            .get(userId="me", id=id, format="full")
            .execute()
        )
    except HttpError as e:
        # re-raise as KeyError on 404, as requested
        if getattr(e, "status_code", None) == 404 or "Not Found" in str(e):
            raise KeyError(id) from e
        raise

    payload = msg.get("payload") or {}
    headers_map = build_headers_dict(payload.get("headers") or [])

    # pull canonical headers (may be missing → default to "")
    subject = headers_map.get("Subject", "")
    from_ = headers_map.get("From", "")
    to = headers_map.get("To", "")
    cc = headers_map.get("Cc", "")
    date = headers_map.get("Date", "")

    # walk parts to get bodies and attachments
    found_bodies: Dict[str, Optional[str]] = {"text/plain": None, "text/html": None}
    attachments: List[GmailAttachment] = []

    # inplace content traversal
    if payload:
        extract_message_content(payload, found_bodies, attachments)

    # optional: download attachment data
    if download_attachments and attachments:
        for att in attachments:
            try:
                att_resp = (
                    service.users()
                    .messages()
                    .attachments()
                    .get(userId="me", messageId=id, id=att.attachment_id)
                    .execute()
                )
                # Gmail returns `data` in base64url
                att.data_base64 = att_resp.get("data")
            except HttpError:
                # don’t break the whole fetch if one attachment fails
                att.data_base64 = None

    # final assembly
    return GmailMessage(
        message_id=msg.get("id"),
        thread_id=msg.get("threadId"),
        label_ids=msg.get("labelIds", []),
        internal_date_ms=int(msg.get("internalDate") or 0),
        subject=subject,
        from_=from_,
        to=to,
        cc=cc,
        date=date,
        headers=headers_map,
        text_body=found_bodies.get("text/plain"),
        html_body=found_bodies.get("text/html"),
        snippet=msg.get("snippet", ""),
        attachments=attachments,
    )