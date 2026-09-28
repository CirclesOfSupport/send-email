"""One JSON line per call, on stdout, which Cloud Logging stores as jsonPayload.

What a line may carry is fixed here: the kind, recipient DOMAINS,
counts, timing, the outcome and the relay's own reply. Never the body, the
subject, a full address, or anything about a subscriber.
"""

from __future__ import annotations

import json
import sys

SEVERITY = {"sent": "INFO", "refused": "WARNING", "failed": "ERROR"}
MARKER = {"sent": "SEND_EMAIL_SENT", "refused": "SEND_EMAIL_REFUSED", "failed": "SEND_EMAIL_FAILED"}

ALLOWED_FIELDS = (
    "outcome", "reason", "kind", "recipient_count", "recipient_domains",
    "attempts", "duration_ms", "smtp_code", "smtp_reply", "message_id", "http_status",
)


def emit(**fields) -> dict:
    outcome = fields["outcome"]
    record = {"severity": SEVERITY[outcome], "event": "send_email"}
    for key in ALLOWED_FIELDS:
        if key in fields:
            record[key] = fields[key]
    record["message"] = f"{MARKER[outcome]} kind={record.get('kind')} reason={record.get('reason')}"
    sys.stdout.write(json.dumps(record, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return record


def emit_problems(problems) -> None:
    record = {"severity": "ERROR", "event": "send_email_config",
              "problems": list(problems),
              "message": "SEND_EMAIL_MISCONFIGURED " + "; ".join(problems)}
    sys.stdout.write(json.dumps(record, separators=(",", ":")) + "\n")
    sys.stdout.flush()
