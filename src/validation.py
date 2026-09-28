"""Who may call, and what a call may ask for."""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass

from config import is_valid_address

SECRET_HEADER = "X-Webhook-Secret"
KIND_RE = re.compile(r"^[a-z0-9_-]{1,40}$")
MAX_SUBJECT_CHARS = 500
MAX_BODY_CHARS = 100_000


def is_authorized(provided: str | None, secret: str) -> bool:
    """Constant-time check of the shared secret. An empty secret authorizes nothing."""
    if not secret or not secret.strip() or provided is None:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), secret.encode("utf-8"))


class BadRequest(Exception):
    def __init__(self, field: str, detail: str):
        super().__init__(f"{field}: {detail}")
        self.field = field
        self.detail = detail


@dataclass(frozen=True)
class SendRequest:
    recipients: tuple
    subject: str
    body: str
    kind: str

    @property
    def recipient_domains(self) -> list:
        return sorted({r.rsplit("@", 1)[1].lower() for r in self.recipients})


def safe_kind(payload) -> str | None:
    """The kind, for logging, only if it is a well-formed kind."""
    if isinstance(payload, dict):
        kind = payload.get("kind")
        if isinstance(kind, str) and KIND_RE.match(kind):
            return kind
    return None


def _recipients(value, max_recipients: int) -> tuple:
    if isinstance(value, str):
        parts = re.split(r"[,;]", value)
    elif isinstance(value, list):
        if not all(isinstance(p, str) for p in value):
            raise BadRequest("to", "every recipient must be a string")
        parts = value
    else:
        raise BadRequest("to", "must be an address, a comma-separated list, or a JSON list")

    seen, out = set(), []
    for part in parts:
        address = part.strip()
        if not address:
            continue
        if not is_valid_address(address):
            raise BadRequest("to", "contains a value that is not a single email address")
        if address.lower() not in seen:
            seen.add(address.lower())
            out.append(address)
    if not out:
        raise BadRequest("to", "no recipient")
    if len(out) > max_recipients:
        raise BadRequest("to", f"more than {max_recipients} recipients")
    return tuple(out)


def parse_send_request(payload, max_recipients: int) -> SendRequest:
    if not isinstance(payload, dict):
        raise BadRequest("body", "request body must be a JSON object")

    kind = payload.get("kind")
    if not isinstance(kind, str) or not KIND_RE.match(kind):
        raise BadRequest("kind", "required; lowercase letters, digits, _ or -, at most 40")

    recipients = _recipients(payload.get("to"), max_recipients)

    subject = payload.get("subject")
    if not isinstance(subject, str):
        raise BadRequest("subject", "required string")
    subject = re.sub(r"\s*[\r\n]+\s*", " ", subject).strip()
    if not subject:
        raise BadRequest("subject", "empty")
    if len(subject) > MAX_SUBJECT_CHARS:
        raise BadRequest("subject", f"longer than {MAX_SUBJECT_CHARS} characters")

    body = payload.get("body")
    if not isinstance(body, str):
        raise BadRequest("body", "required string")
    if not body.strip():
        raise BadRequest("body", "empty")
    if len(body) > MAX_BODY_CHARS:
        raise BadRequest("body", f"longer than {MAX_BODY_CHARS} characters")

    return SendRequest(recipients=recipients, subject=subject, body=body, kind=kind)

