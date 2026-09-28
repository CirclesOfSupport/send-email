"""send-email: the service our TextIt flows call to send an email.

POST /send   header X-Webhook-Secret; JSON {to, subject, body, kind}
GET  /health

Every call writes one log line (see logline.py) and gets a status the flow's
webhook step can branch on: 200 when the relay accepted the message, a non-2xx
status for everything else, so a failed send takes the flow's Failure exit.
"""

from __future__ import annotations

import os
import ssl
import time

from flask import Flask, jsonify, request

import logline
import mailer
from config import load_config
from validation import SECRET_HEADER, BadRequest, is_authorized, parse_send_request, safe_kind

app = Flask(__name__)

# Replaced in tests to trust a local test certificate. Production verifies the
# relay's certificate against the system trust store.
TLS_CONTEXT_FACTORY = ssl.create_default_context


def _status_for_failure(reason: str) -> int:
    return 504 if "timeout" in reason else 502


def _finish(status: int, body: dict, **log_fields):
    log_fields.setdefault("http_status", status)
    logline.emit(**log_fields)
    return jsonify(body), status


@app.get("/health")
def health():
    cfg = load_config()
    if not cfg.ok:
        logline.emit_problems(cfg.problems)
        return jsonify({"status": "misconfigured"}), 500
    return jsonify({"status": "ok", "auth_mode": cfg.smtp_auth_mode}), 200


@app.post("/send")
def send():
    started = time.monotonic()
    cfg = load_config()

    def elapsed_ms():
        return int((time.monotonic() - started) * 1000)

    if not cfg.webhook_secret.strip():
        logline.emit_problems(cfg.problems)
        return _finish(500, {"status": "refused", "reason": "misconfigured"},
                       outcome="refused", reason="misconfigured", duration_ms=elapsed_ms())

    if not is_authorized(request.headers.get(SECRET_HEADER), cfg.webhook_secret):
        return _finish(401, {"status": "refused", "reason": "unauthorized"},
                       outcome="refused", reason="unauthorized", duration_ms=elapsed_ms())

    if not cfg.ok:
        logline.emit_problems(cfg.problems)
        return _finish(500, {"status": "refused", "reason": "misconfigured"},
                       outcome="refused", reason="misconfigured", duration_ms=elapsed_ms())

    payload = request.get_json(force=True, silent=True)
    kind = safe_kind(payload)
    try:
        req = parse_send_request(payload, cfg.max_recipients)
    except BadRequest as exc:
        return _finish(400, {"status": "refused", "reason": "bad_request", "field": exc.field,
                             "detail": exc.detail},
                       outcome="refused", reason=f"bad_request_{exc.field}", kind=kind,
                       duration_ms=elapsed_ms())

    who = {"kind": req.kind, "recipient_count": len(req.recipients),
           "recipient_domains": req.recipient_domains}

    msg, message_id = mailer.build_message(cfg, req)
    result = mailer.send(cfg, msg, req.recipients, deadline=started + cfg.send_deadline,
                         tls_context=TLS_CONTEXT_FACTORY())

    fields = dict(who, attempts=result.attempts, message_id=message_id,
                  smtp_code=result.smtp_code, smtp_reply=result.smtp_reply)
    if result.outcome == "sent":
        return _finish(200, {"status": "sent", "message_id": message_id},
                       outcome="sent", reason="sent", duration_ms=elapsed_ms(), **fields)

    status = _status_for_failure(result.reason)
    return _finish(status, {"status": "failed", "reason": result.reason,
                            "smtp_code": result.smtp_code, "message_id": message_id},
                   outcome="failed", reason=result.reason, duration_ms=elapsed_ms(), **fields)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
