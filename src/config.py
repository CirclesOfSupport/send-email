"""Service configuration, read from the environment on every request.

Nothing secret has a default. Secrets (WEBHOOK_SECRET, SMTP_PASSWORD) reach the
container from Secret Manager through Cloud Run's --set-secrets, never from this
repository.

A configuration problem never opens the service up: load_config() lists every
problem it finds, and while any problem exists the service refuses to send.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Mapping

AUTH_MODES = ("ip", "password")

# TextIt gives a webhook 15 seconds. The service must answer before that, so the
# send deadline may not be set at or above 14 seconds.
MAX_DEADLINE_SECONDS = 14.0

ADDRESS_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


def is_valid_address(value: str) -> bool:
    """A single bare mailbox: no display name, no whitespace, no line breaks."""
    return isinstance(value, str) and len(value) <= 254 and ADDRESS_RE.match(value) is not None


@dataclass(frozen=True)
class Config:
    webhook_secret: str
    smtp_host: str
    smtp_port: int
    smtp_auth_mode: str
    smtp_username: str
    smtp_password: str
    ehlo_name: str
    from_name: str
    from_address: str
    envelope_from: str
    max_recipients: int
    send_deadline: float
    smtp_timeout: float
    problems: tuple = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return not self.problems


def _number(env: Mapping[str, str], key: str, default, cast, problems: list):
    raw = env.get(key, "").strip()
    if raw == "":
        return default
    try:
        return cast(raw)
    except ValueError:
        problems.append(f"{key} is not a number")
        return default


def load_config(env: Mapping[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    problems: list[str] = []

    webhook_secret = env.get("WEBHOOK_SECRET", "")
    if not webhook_secret.strip():
        problems.append("WEBHOOK_SECRET is not set")

    smtp_host = env.get("SMTP_HOST", "smtp-relay.gmail.com").strip()
    smtp_port = _number(env, "SMTP_PORT", 587, int, problems)

    smtp_auth_mode = env.get("SMTP_AUTH_MODE", "").strip()
    if smtp_auth_mode not in AUTH_MODES:
        problems.append("SMTP_AUTH_MODE must be 'ip' or 'password'")
    smtp_username = env.get("SMTP_USERNAME", "").strip()
    smtp_password = env.get("SMTP_PASSWORD", "")
    if smtp_auth_mode == "password" and (not smtp_username or not smtp_password):
        problems.append("SMTP_USERNAME and SMTP_PASSWORD are required when SMTP_AUTH_MODE is password")

    ehlo_name = env.get("SMTP_EHLO_NAME", "earlyalert.me").strip()
    if not ehlo_name or ehlo_name.lower() in ("localhost", "smtp-relay.gmail.com"):
        problems.append("SMTP_EHLO_NAME must be one of our domain names")

    from_name = env.get("FROM_NAME", "Early Alert").strip()
    from_address = env.get("FROM_ADDRESS", "noreply@earlyalert.me").strip()
    if not is_valid_address(from_address):
        problems.append("FROM_ADDRESS is not an email address")
    envelope_from = env.get("ENVELOPE_FROM", "").strip() or from_address
    if not is_valid_address(envelope_from):
        problems.append("ENVELOPE_FROM is not an email address")
    if any(c in from_name for c in "\r\n"):
        problems.append("FROM_NAME contains a line break")

    max_recipients = _number(env, "MAX_RECIPIENTS", 10, int, problems)
    if not 1 <= max_recipients <= 100:
        problems.append("MAX_RECIPIENTS must be between 1 and 100")

    send_deadline = _number(env, "SEND_DEADLINE_SECONDS", 12.0, float, problems)
    if not 0 < send_deadline < MAX_DEADLINE_SECONDS:
        problems.append(f"SEND_DEADLINE_SECONDS must be above 0 and below {MAX_DEADLINE_SECONDS:g}")
    smtp_timeout = _number(env, "SMTP_TIMEOUT_SECONDS", 5.0, float, problems)
    if not 0 < smtp_timeout <= send_deadline:
        problems.append("SMTP_TIMEOUT_SECONDS must be above 0 and not above SEND_DEADLINE_SECONDS")

    return Config(
        webhook_secret=webhook_secret,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_auth_mode=smtp_auth_mode,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        ehlo_name=ehlo_name,
        from_name=from_name,
        from_address=from_address,
        envelope_from=envelope_from,
        max_recipients=max_recipients,
        send_deadline=send_deadline,
        smtp_timeout=smtp_timeout,
        problems=tuple(problems),
    )
