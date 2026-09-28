"""One message, one SMTP transaction, answered inside the deadline.

- STARTTLS is required. A server that does not offer it gets nothing.
- All recipients are accepted, or the message is not sent: every RCPT is checked
  before DATA, and one refusal cancels the transaction (no partial delivery).
- At most two attempts. The second only for a transient failure (a 4xx reply, or
  a connection problem before DATA) and only if at least RETRY_MIN_SECONDS remain.
  A 5xx is final.
- Once DATA has been sent, a lost connection or timeout is an UNKNOWN outcome:
  it is reported as a failure and never retried, so this service never sends the
  same message twice on its own and never reports an unknown outcome as sent.
"""

from __future__ import annotations

import smtplib
import ssl
import time
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

RETRY_MIN_SECONDS = 3.0
MAX_ATTEMPTS = 2


@dataclass
class SendResult:
    outcome: str            # "sent" | "failed"
    reason: str             # "sent" or why not
    attempts: int
    smtp_code: int | None = None
    smtp_reply: str | None = None


class _Transient(Exception):
    def __init__(self, reason, code=None, reply=None):
        super().__init__(reason)
        self.reason, self.code, self.reply = reason, code, reply


class _Final(Exception):
    def __init__(self, reason, code=None, reply=None):
        super().__init__(reason)
        self.reason, self.code, self.reply = reason, code, reply


def build_message(cfg, req) -> tuple[EmailMessage, str]:
    domain = cfg.from_address.rsplit("@", 1)[1]
    message_id = make_msgid(domain=domain)
    msg = EmailMessage()
    msg["From"] = formataddr((cfg.from_name, cfg.from_address))
    msg["To"] = ", ".join(req.recipients)
    msg["Subject"] = req.subject
    msg["Date"] = formatdate(usegmt=True)
    msg["Message-ID"] = message_id
    msg.set_content(req.body)
    return msg, message_id


def _reply_text(raw) -> str:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return " ".join(str(raw).split())[:200]


def _classify(code: int, reply, stage: str):
    text = _reply_text(reply)
    if 400 <= code < 500:
        return _Transient(f"relay_{stage}_{code}", code, text)
    return _Final(f"relay_{stage}_{code}", code, text)


def _is_timeout(exc) -> bool:
    seen = 0
    while exc is not None and seen < 5:
        if isinstance(exc, TimeoutError):
            return True
        exc = exc.__cause__ or exc.__context__
        seen += 1
    return False


class _Clock:
    def __init__(self, deadline: float, per_op: float):
        self.deadline, self.per_op = deadline, per_op

    def remaining(self) -> float:
        return self.deadline - time.monotonic()

    def op_timeout(self) -> float:
        left = self.remaining()
        if left <= 0:
            raise TimeoutError("deadline reached")
        return min(left, self.per_op)

    def arm(self, smtp):
        if smtp.sock is not None:
            smtp.sock.settimeout(self.op_timeout())


def _attempt(cfg, msg: EmailMessage, recipients, clock: _Clock, tls_context, smtp_class):
    stage = "connect"
    smtp = None
    try:
        smtp = smtp_class(cfg.smtp_host, cfg.smtp_port, local_hostname=cfg.ehlo_name,
                          timeout=clock.op_timeout())
        stage = "ehlo"
        clock.arm(smtp)
        code, reply = smtp.ehlo()
        if code != 250:
            raise _classify(code, reply, "ehlo")
        if not smtp.has_extn("starttls"):
            raise _Final("starttls_unavailable")
        stage = "starttls"
        clock.arm(smtp)
        code, reply = smtp.starttls(context=tls_context)
        if code != 220:
            raise _classify(code, reply, "starttls")
        clock.arm(smtp)
        code, reply = smtp.ehlo()
        if code != 250:
            raise _classify(code, reply, "ehlo")
        if cfg.smtp_auth_mode == "password":
            stage = "auth"
            clock.arm(smtp)
            smtp.login(cfg.smtp_username, cfg.smtp_password)
        stage = "mail"
        clock.arm(smtp)
        code, reply = smtp.mail(cfg.envelope_from)
        if code != 250:
            raise _classify(code, reply, "mail")
        stage = "rcpt"
        worst = None
        for address in recipients:
            clock.arm(smtp)
            code, reply = smtp.rcpt(address)
            if code not in (250, 251) and (worst is None or code > worst[0]):
                worst = (code, reply)
        if worst is not None:
            try:
                clock.arm(smtp)
                smtp.rset()
            except Exception:
                pass
            raise _classify(worst[0], worst[1], "rcpt")
        payload = msg.as_bytes()
        clock.arm(smtp)
        stage = "data"   # from here on, the relay may already hold the message
        code, reply = smtp.data(payload)
        if code != 250:
            raise _classify(code, reply, "data")
        try:
            clock.arm(smtp)
            smtp.quit()
        except Exception:
            pass
        smtp = None
    except (_Transient, _Final):
        raise
    except smtplib.SMTPAuthenticationError as exc:
        raise _Final("relay_auth_refused", exc.smtp_code, _reply_text(exc.smtp_error))
    except smtplib.SMTPResponseException as exc:
        raise _classify(exc.smtp_code, exc.smtp_error, stage)
    except ssl.SSLCertVerificationError as exc:
        raise _Final("tls_certificate_invalid", None, _reply_text(exc.verify_message or exc))
    except (TimeoutError, OSError, smtplib.SMTPException) as exc:
        # socket.timeout is TimeoutError; ConnectionError and ssl.SSLError are OSError.
        # smtplib wraps a read timeout in SMTPServerDisconnected, so look at the cause.
        kind = "timeout" if _is_timeout(exc) else "connection"
        if stage == "data":
            raise _Final(f"unknown_after_data_{kind}")
        raise _Transient(f"{kind}_at_{stage}")
    finally:
        if smtp is not None:
            try:
                smtp.close()
            except Exception:
                pass


def send(cfg, msg: EmailMessage, recipients, deadline: float,
         tls_context: ssl.SSLContext | None = None, smtp_class=smtplib.SMTP) -> SendResult:
    tls_context = tls_context or ssl.create_default_context()
    clock = _Clock(deadline, cfg.smtp_timeout)
    attempts = 0
    last: _Transient | None = None
    while attempts < MAX_ATTEMPTS:
        if attempts > 0 and clock.remaining() < RETRY_MIN_SECONDS:
            break
        if clock.remaining() <= 0:
            break
        attempts += 1
        try:
            _attempt(cfg, msg, recipients, clock, tls_context, smtp_class)
            return SendResult("sent", "sent", attempts)
        except _Final as exc:
            return SendResult("failed", exc.reason, attempts, exc.code, exc.reply)
        except _Transient as exc:
            last = exc
    if last is None:
        return SendResult("failed", "timeout_before_attempt", attempts)
    return SendResult("failed", last.reason, attempts, last.code, last.reply)
