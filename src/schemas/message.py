from dataclasses import dataclass
from textwrap import indent
from typing import Dict, List, Optional


@dataclass
class GmailAttachment:
    attachment_id: str
    filename: str
    mime_type: str
    size: int  # bytes
    data_base64: Optional[str] = None   # populate on download

    def __str__(self) -> str:
        """Format output string."""
        return f"{self.filename} ({self.mime_type}, {self.size} bytes)"


@dataclass
class GmailMessage:
    message_id: str
    thread_id: str
    label_ids: List[str]
    internal_date_ms: int

    subject: str
    from_: str
    to: List[str]
    cc: List[str]
    date: str
    headers: Dict[str, str]

    # decoded bodies (utf-8 best-effort)
    text_body: Optional[str]
    html_body: Optional[str]

    # metadata
    snippet: str

    # attachment metadata (download on demand)
    attachments: List[GmailAttachment]

    def __str__(self) -> str:
        """Format output string."""
        header = (
            f"Message ID: {self.message_id}\n"
            f"Thread ID: {self.thread_id}\n"
            f"Date: {self.date}\n"
            f"From: {self.from_}\n"
            f"To: {self.to}\n"
            f"Cc: {self.cc}\n"
            f"Subject: {self.subject}\n"
            f"Labels: {', '.join(self.label_ids) if self.label_ids else '(none)'}\n"
        )

        bodies = []
        if self.text_body:
            bodies.append("Text Body:\n" + indent(self.text_body.strip(), "  "))
        if self.html_body:
            bodies.append("HTML Body:\n" + indent(self.html_body.strip()[:200] + "...", "  "))

        attachments = (
            "Attachments:\n" + indent("\n".join(str(a) for a in self.attachments), "  ")
            if self.attachments else "Attachments: (none)"
        )

        return "\n".join([header, "\n".join(bodies), attachments])