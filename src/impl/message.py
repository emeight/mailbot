import base64
import mimetypes
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from googleapiclient.discovery import Resource
from googleapiclient.errors import HttpError

from src.schemas.message import GmailAttachment, GmailMessage


def build_headers_dict(payload_headers: List[Dict]) -> Dict[str, Any]:
    """Normalize headers into a case-insensitive dict (keys as canonical names)."""
    out: Dict[str, str] = {}
    for h in payload_headers or []:
        name = (h.get("name") or "").strip()
        value = (h.get("value") or "").strip()
        if name:
            # preserve the last occurrence; Gmail may repeat some headers
            out[name] = value
    return out


def list_emails_from_header(value: Optional[str]) -> List[str]:
    """Parse a header field into a list of email address."""
    return [addr for _, addr in getaddresses([value or ""]) if addr]


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


def fetch_sender_email(service: Resource, id: str) -> str:
    """Fetch only the sender email address for a message.
    
    Parameters
    ----------
    service : Resource
        googleapiclient resource object.
    id : str
        Unique message identifier.
        
    Returns
    -------
    str
        Sender email address.

    """
    
    try:
        # Only fetch metadata with the From header
        msg = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=id,
                format="metadata",
                metadataHeaders=["From"]
            )
            .execute()
        )
        
        # extract From header
        headers = msg.get("payload", {}).get("headers", [])
        from_header = next(
            (h["value"] for h in headers if h["name"].lower() == "from"),
            ""
        )
        
        # parse out just the email address
        _, sender_email = parseaddr(from_header)
        return sender_email
        
    except HttpError as e:
        if getattr(e, "status_code", None) == 404 or "Not Found" in str(e):
            raise KeyError(id) from e
        raise RuntimeError


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
        resp: Dict[str, Optional[Union[Dict[str, str], str, int]]] = (
            service.users()
            .messages()
            .list(
                userId="me",
                labelIds=["INBOX"],
                q="is:unread",
                maxResults=500,
                pageToken=page_token,
            )
            .execute()
        )

        for m in resp.get("messages", []):
            unread_map[m["id"]] = {"threadId": m["threadId"]}

        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    # returns dict of dicts keyed by message id {"id": {"threadId": "abc123"}}
    return unread_map


def fetch_message_by_id(
    service: Resource, id: str, download_attachments: bool = False
) -> GmailMessage:
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
            service.users().messages().get(userId="me", id=id, format="full").execute()
        )
    except HttpError as e:
        # re-raise as KeyError on 404, as requested
        if getattr(e, "status_code", None) == 404 or "Not Found" in str(e):
            raise KeyError(id) from e
        raise RuntimeError

    payload = msg.get("payload") or {}
    headers_map = build_headers_dict(payload.get("headers") or [])

    # pull canonical headers (may be missing -> default to "")
    subject = headers_map.get("Subject", "")
    date = headers_map.get("Date", "")

    # pull out addresses
    from_header = headers_map.get("From", "")
    to_header = headers_map.get("To", "")
    cc_header = headers_map.get("Cc", "")

    from_ = parseaddr(from_header)[1] if from_header else []
    to_addresses = getaddresses([to_header]) if to_header else []
    cc_addresses = getaddresses([cc_header]) if cc_header else []

    to_emails = [email for name, email in to_addresses]
    cc_emails = [email for name, email in cc_addresses]

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
        to=to_emails,
        cc=cc_emails,
        date=date,
        headers=headers_map,
        text_body=found_bodies.get("text/plain"),
        html_body=found_bodies.get("text/html"),
        snippet=msg.get("snippet", ""),
        attachments=attachments,
    )


def build_message_with_attachments(
    to: List[str],
    subject: str,
    body_text: str,
    *,
    cc: Optional[List[str]] = None,
    attachment_paths: Optional[List[str]] = None,
    body_html: Optional[str] = None,
    reply_to: Optional[str] = None,
    # --- reply-specific options ---
    in_reply_to_message_id: Optional[str] = None,
    references_chain: Optional[str] = None,
    ensure_re_prefix: bool = True,
) -> str:
    """Build a base64url-encoded MIME email for Gmail API (new or reply).

    Parameters
    ----------
    to : List[str]
        Primary recipients of the email.

    subject : str
        Subject line (will be prefixed with "Re: " if replying and `ensure_re_prefix=True`).

    body_text : str
        Plain text body.

    cc : Optional[List[str]]
        Additional recipients (comma-joined into Cc).

    attachment_paths : Optional[List[str]]
        Files to attach.

    body_html : Optional[str]
        Optional HTML alternative body (added via multipart/alternative).

    reply_to : Optional[str]
        "Reply-To" header value to include on the outgoing message.

    in_reply_to_message_id : Optional[str]
        The original message's "Message-Id" (or "Message-ID") header value. If set,
        this builder adds `In-Reply-To` and extends `References`.

    references_chain : Optional[str]
        The original message's "References" header value (if any). If provided,
        the builder appends `in_reply_to_message_id` if it isn't already present.

    ensure_re_prefix : bool
        If True and replying, prefix subject with "Re: " when missing.
        Defaults to False.

    Returns
    -------
    str
        Base64url-encoded raw string suitable for Gmail API `users.messages.send`.

    """
    # subject handling (ensure "Re: " for replies if desired)
    final_subject = subject
    if (
        in_reply_to_message_id
        and ensure_re_prefix
        and subject
        and not subject.lower().startswith("re:")
    ):
        final_subject = f"Re: {subject}"

    # build MIME
    msg = EmailMessage()
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = final_subject

    # reply/threading headers
    if in_reply_to_message_id:
        msg["In-Reply-To"] = in_reply_to_message_id
        if references_chain:
            refs = references_chain
            if in_reply_to_message_id not in refs:
                refs = (refs + " " + in_reply_to_message_id).strip()
            msg["References"] = refs
        else:
            msg["References"] = in_reply_to_message_id

    # bodies
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    # attachments
    for p in attachment_paths or []:
        path = Path(p)
        ctype, enc = mimetypes.guess_type(path)
        if ctype is None or enc is not None:
            ctype = "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        with path.open("rb") as fh:
            msg.add_attachment(
                fh.read(),
                maintype=maintype,
                subtype=subtype,
                filename=path.name,
            )

    # return base64url-encoded raw
    return base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")


def send_raw_message(
    service: Resource, raw: str, *, thread_id: Optional[str] = None
) -> Dict[str, str]:
    """Send a Gmail MIME message (base64url `raw`). Include `thread_id` to reply.

    Parameters
    ----------
    raw : str
        Base64 encoded message content.

    thread_id : Optional[str]
        Original thread identifier for replies.
        Defaults to None.

    Raises
    ------
    RuntimeError
        On unsuccessful message send.

    Returns
    -------
    Dict[str, str]
        {"id": ..., "threadId": ...} of the sent message.

    """
    body = {"raw": raw}
    if thread_id:
        body["threadId"] = thread_id  # keep in same thread for replies

    try:
        resp = service.users().messages().send(userId="me", body=body).execute()
    except HttpError as e:
        raise RuntimeError(f"Gmail send failed: {e}") from e

    msg_id = resp.get("id")
    resp_thread_id = resp.get("threadId")
    if not msg_id or not resp_thread_id:
        raise RuntimeError(
            f"Gmail send succeeded but response missing id/threadId: {resp!r}"
        )

    return {"id": msg_id, "threadId": resp_thread_id}


def send_new_message(
    service: Resource,
    to: List[str],
    subject: str,
    body_text: str,
    *,
    cc: Optional[List[str]] = None,
    attachment_paths: Optional[List[str]] = None,
    body_html: Optional[str] = None,
    reply_to: Optional[str] = None,
) -> Dict[str, str]:
    """Send a new email (non-reply).

    Parameters
    ----------
    service : Resource
        googleapiclient resource object.

    to : List[str]
        Primary recipients email.

    subject : str
        Message subject.

    body_text : str
        Message body string content.

    cc : Optional[List[str]]
        Additional recipients.
        Defaults to None.

    attachment_paths : Optional[List[str]]
        Paths to attached files.
        Defaults to None.

    body_html : Optional[str]
        HTML content to replace body text.
        Defaults to None.

    reply_to : Optional[str]
        Address to which replies should be directed.
        Defaults to None.

    Raises
    ------
    RuntimeError
        On unsuccessful message send.

    Returns
    -------
    Dict[str, str]
        {"id": ..., "threadId": ...} of the sent message.

    """
    # build raw message string
    raw = build_message_with_attachments(
        to=to,
        subject=subject,
        body_text=body_text,
        cc=cc,
        attachment_paths=attachment_paths,
        body_html=body_html,
        reply_to=reply_to,
    )

    return send_raw_message(service, raw)


def reply_to_existing_message(
    service: Resource,
    original: GmailMessage,
    body_text: str,
    *,
    reply_all: bool = False,
    body_html: Optional[str] = None,
    attachment_paths: Optional[List[str]] = None,
) -> Dict[str, str]:
    """Reply (or reply-all) to an existing message represented by GmailMessage.

    Returns None on success; raises RuntimeError on send failure.

    Parameters
    ----------
    service : Resource
        googleapiclient resource object.

    original : GmailMessage
        The original message object to reply to.

    body_text : str
        Plain-text body for the reply.

    reply_all : bool
        If True, include original To/Cc in Cc (excluding yourself and the primary reply target).

    body_html : Optional[str]
        Optional HTML alternative body.

    attachment_paths : Optional[List[str]]
        Optional file paths to attach.

    Raises
    ------
    RuntimeError
        On unsuccessful message send.

    Returns
    -------
    Dict[str, str]
        {"id": ..., "threadId": ...} of the sent message.

    """
    # build cc list for reply-all
    cc_addrs: List[str] = []
    reply_to_addr = original.from_  # reply to the sender

    if reply_all:
        # parse all original recipients
        from email.utils import getaddresses
        
        to_addresses = getaddresses([original.to]) if original.to else []
        cc_addresses = getaddresses([original.cc]) if original.cc else []
        
        # extract just email addresses
        to_emails = [email for _, email in to_addresses]
        cc_emails = [email for _, email in cc_addresses]
        
        # combine all recipients except yourself and the original sender
        all_recipients = set(to_emails + cc_emails)
        all_recipients.discard(reply_to_addr)  # don't CC the person we're replying to
        
        cc_addrs = sorted(all_recipients)

    # threading headers for the reply
    subject = original.subject or ""
    msg_id = original.headers.get("Message-Id") or original.headers.get("Message-ID")
    refs = original.headers.get("References", "")

    # build raw message string
    raw = build_message_with_attachments(
        to=[reply_to_addr],  # must be iterable
        subject=subject,
        body_text=body_text,
        cc=cc_addrs or None,
        attachment_paths=list(attachment_paths) if attachment_paths else None,
        body_html=body_html,
        in_reply_to_message_id=msg_id,
        references_chain=refs,
        ensure_re_prefix=True,
    )

    # send the message
    return send_raw_message(service, raw, thread_id=original.thread_id)
