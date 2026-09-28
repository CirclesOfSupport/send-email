"""Run from the repo root:  python -m pytest -q tests

Every send test talks to a real SMTP server on 127.0.0.1 (aiosmtpd), with STARTTLS
on a throwaway certificate made here. Nothing leaves the machine.
"""

import asyncio
import datetime
import ipaddress
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import config  # noqa: E402
import main  # noqa: E402
import mailer  # noqa: E402

SECRET = "test-secret-value"
BODY = "Subscriber reported distress at 3:14 pm. Please follow up with Jordan Q. Testperson."
SUBJECT = "Triage request for Jordan Q. Testperson"
LOGAN = "logan.test@example.org"
OTHER = "counselor@counseling.example.com"


# --------------------------------------------------------------------------- certificate

def _make_cert(tmpdir):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path = os.path.join(tmpdir, "cert.pem")
    key_path = os.path.join(tmpdir, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path


@pytest.fixture(scope="session")
def certs():
    d = tempfile.mkdtemp()
    return _make_cert(d)


@pytest.fixture
def client_tls(certs, monkeypatch):
    cert_path, _ = certs

    def factory():
        ctx = ssl.create_default_context(cafile=cert_path)
        return ctx
    monkeypatch.setattr(main, "TLS_CONTEXT_FACTORY", factory)
    return factory


# --------------------------------------------------------------------------- SMTP server

class Handler:
    """Records what the server saw; scripted replies per stage."""

    def __init__(self):
        self.ehlo_names = []
        self.mail_from = []
        self.rcpts = []
        self.messages = []          # (mail_from, rcpt_tos, content bytes)
        self.authenticated = []
        self.tls_at_mail = []
        self.rcpt_script = []       # list of codes to return in order, then 250
        self.mail_script = []
        self.data_script = []
        self.data_delay = 0.0

    async def handle_EHLO(self, server, session, envelope, hostname, responses):
        self.ehlo_names.append(hostname)
        session.host_name = hostname
        return responses

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        self.mail_from.append(address)
        self.tls_at_mail.append(session.ssl is not None)
        self.authenticated.append(bool(session.authenticated))
        if self.mail_script:
            code = self.mail_script.pop(0)
            if code != 250:
                return f"{code} scripted mail reply"
        envelope.mail_from = address
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        self.rcpts.append(address)
        if self.rcpt_script:
            code = self.rcpt_script.pop(0)
            if code != 250:
                return f"{code} scripted rcpt reply"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        if self.data_delay:
            await asyncio.sleep(self.data_delay)
        if self.data_script:
            code = self.data_script.pop(0)
            if code != 250:
                return f"{code} scripted data reply"
        self.messages.append((envelope.mail_from, list(envelope.rcpt_tos), envelope.content))
        return "250 2.0.0 accepted"


def _authenticator(server, session, envelope, mechanism, auth_data):
    if isinstance(auth_data, LoginPassword) and auth_data.login == b"relay-user" \
            and auth_data.password == b"relay-pass":
        return AuthResult(success=True)
    return AuthResult(success=False, handled=False)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def smtp_server(certs):
    cert_path, key_path = certs
    started = []

    def start(tls=True):
        handler = Handler()
        kwargs = {}
        if tls:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(cert_path, key_path)
            kwargs = dict(tls_context=ctx, require_starttls=True, auth_require_tls=True,
                          authenticator=_authenticator)
        else:
            kwargs = dict(auth_require_tls=False, authenticator=_authenticator)
        port = _free_port()
        ctl = Controller(handler, hostname="127.0.0.1", port=port, **kwargs)
        ctl.start()
        started.append(ctl)
        return handler, port

    yield start
    for ctl in started:
        ctl.stop()


# --------------------------------------------------------------------------- app helpers

@pytest.fixture
def env(monkeypatch):
    for key in list(os.environ):
        if key in ("ENVIRONMENT", "WEBHOOK_SECRET", "RECIPIENT_ALLOWLIST", "SMTP_HOST", "SMTP_PORT",
                   "SMTP_AUTH_MODE", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_EHLO_NAME",
                   "FROM_NAME", "FROM_ADDRESS", "ENVELOPE_FROM", "MAX_RECIPIENTS",
                   "SEND_DEADLINE_SECONDS", "SMTP_TIMEOUT_SECONDS"):
            monkeypatch.delenv(key, raising=False)

    def set_env(port=25, **overrides):
        values = {"ENVIRONMENT": "live", "WEBHOOK_SECRET": SECRET, "SMTP_HOST": "localhost",
                  "SMTP_PORT": str(port), "SMTP_AUTH_MODE": "ip"}
        values.update(overrides)
        for k, v in values.items():
            if v is None:
                monkeypatch.delenv(k, raising=False)
            else:
                monkeypatch.setenv(k, v)
    return set_env


@pytest.fixture
def app_client():
    main.app.config["TESTING"] = True
    return main.app.test_client()


def payload(**overrides):
    p = {"to": LOGAN, "subject": SUBJECT, "body": BODY, "kind": "triage_request"}
    p.update(overrides)
    return {k: v for k, v in p.items() if v is not None}


def post(client, body=None, secret=SECRET, raw=None):
    headers = {} if secret is None else {"X-Webhook-Secret": secret}
    if raw is not None:
        return client.post("/send", data=raw, headers=headers, content_type="application/json")
    return client.post("/send", json=body if body is not None else payload(), headers=headers)


def log_lines(capsys):
    out = capsys.readouterr().out
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


def send_lines(lines):
    return [r for r in lines if r.get("event") == "send_email"]


# =========================================================================== 1. who may call

def test_missing_secret_header_is_refused(env, app_client, smtp_server, client_tls, capsys):
    handler, port = smtp_server()
    env(port)
    r = post(app_client, secret=None)
    assert r.status_code == 401
    assert handler.mail_from == []
    [line] = send_lines(log_lines(capsys))
    assert line["outcome"] == "refused" and line["reason"] == "unauthorized"


def test_wrong_secret_is_refused(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port)
    assert post(app_client, secret="nope").status_code == 401
    assert post(app_client, secret=SECRET + "x").status_code == 401
    assert post(app_client, secret="").status_code == 401
    assert handler.mail_from == []


@pytest.mark.parametrize("value", [None, "", "   "])
def test_service_without_secret_refuses_everything(env, app_client, smtp_server, client_tls,
                                                    value, capsys):
    handler, port = smtp_server()
    env(port, WEBHOOK_SECRET=value)
    for header in (None, "", "   ", "anything"):
        r = post(app_client, secret=header)
        assert r.status_code == 500
        assert r.get_json()["reason"] == "misconfigured"
    assert handler.mail_from == []
    assert app_client.get("/health").status_code == 500


def test_is_authorized_rules():
    from validation import is_authorized
    assert is_authorized("abc", "abc")
    assert not is_authorized("abc", "")
    assert not is_authorized("", "")
    assert not is_authorized(None, "abc")
    assert not is_authorized("abd", "abc")


def test_secret_compare_is_constant_time():
    import inspect
    import validation
    assert "compare_digest" in inspect.getsource(validation.is_authorized)


def test_health_is_open_and_reveals_nothing(env, app_client):
    env(25)
    r = app_client.get("/health")
    assert r.status_code == 200
    body = r.get_json()
    assert body == {"status": "ok", "environment": "live", "auth_mode": "ip"}
    assert SECRET not in r.get_data(as_text=True)


# =========================================================================== 2. what may be sent

@pytest.mark.parametrize("override,field", [
    ({"kind": None}, "kind"),
    ({"kind": "Triage Request"}, "kind"),
    ({"kind": "x" * 41}, "kind"),
    ({"to": None}, "to"),
    ({"to": ""}, "to"),
    ({"to": "not-an-address"}, "to"),
    ({"to": "Logan <logan.test@example.org>"}, "to"),
    ({"to": "a@example.org\r\nBcc: evil@example.net"}, "to"),
    ({"to": [LOGAN, 7]}, "to"),
    ({"to": {"a": 1}}, "to"),
    ({"subject": None}, "subject"),
    ({"subject": " \n "}, "subject"),
    ({"subject": "s" * 501}, "subject"),
    ({"body": None}, "body"),
    ({"body": "   "}, "body"),
    ({"body": "b" * 100_001}, "body"),
])
def test_bad_fields_are_refused(env, app_client, smtp_server, client_tls, override, field):
    handler, port = smtp_server()
    env(port)
    r = post(app_client, payload(**override))
    assert r.status_code == 400, r.get_json()
    assert r.get_json()["field"] == field
    assert handler.mail_from == []


def test_non_json_and_non_object_are_refused(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port)
    assert post(app_client, raw="not json").status_code == 400
    assert post(app_client, raw="[1,2]").status_code == 400
    assert handler.mail_from == []


def test_recipient_limit(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port)
    eleven = ",".join(f"p{i}@example.org" for i in range(11))
    r = post(app_client, payload(to=eleven))
    assert r.status_code == 400 and r.get_json()["field"] == "to"
    ten = ",".join(f"p{i}@example.org" for i in range(10))
    assert post(app_client, payload(to=ten)).status_code == 200


def test_recipient_forms_and_dedupe(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port)
    r = post(app_client, payload(to=f" {LOGAN} ; {OTHER}, {LOGAN.upper()} ,"))
    assert r.status_code == 200
    assert handler.rcpts == [LOGAN, OTHER]
    r = post(app_client, payload(to=[LOGAN, OTHER]))
    assert r.status_code == 200


def test_subject_line_breaks_cannot_add_headers(env, app_client, smtp_server, client_tls):
    import email
    from email import policy
    handler, port = smtp_server()
    env(port)
    r = post(app_client, payload(subject="Hello\r\nBcc: evil@example.net\nX-Injected: y"))
    assert r.status_code == 200
    parsed = email.message_from_bytes(handler.messages[0][2], policy=policy.default)
    assert parsed["Bcc"] is None and parsed["X-Injected"] is None
    assert parsed["Subject"] == "Hello Bcc: evil@example.net X-Injected: y"
    assert handler.rcpts == [LOGAN]


# =========================================================================== 3. to whom, per environment

def test_dev_sends_to_allowlisted(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port, ENVIRONMENT="dev", RECIPIENT_ALLOWLIST=f"{LOGAN.upper()}, other@example.org")
    assert post(app_client).status_code == 200
    assert handler.rcpts == [LOGAN]


def test_dev_refuses_whole_message_if_any_recipient_off_list(env, app_client, smtp_server,
                                                             client_tls, capsys):
    handler, port = smtp_server()
    env(port, ENVIRONMENT="dev", RECIPIENT_ALLOWLIST=LOGAN)
    r = post(app_client, payload(to=f"{LOGAN},{OTHER}"))
    assert r.status_code == 403
    assert r.get_json() == {"status": "refused", "reason": "recipient_not_allowed", "not_allowed": 1}
    assert handler.mail_from == [] and handler.rcpts == []
    [line] = send_lines(log_lines(capsys))
    assert line["reason"] == "recipient_not_allowed"
    assert line["recipient_domains"] == ["counseling.example.com", "example.org"]


@pytest.mark.parametrize("allow", [None, "", " , "])
def test_dev_with_empty_allowlist_refuses_everything(env, app_client, smtp_server, client_tls, allow):
    handler, port = smtp_server()
    env(port, ENVIRONMENT="dev", RECIPIENT_ALLOWLIST=allow)
    r = post(app_client)
    assert r.status_code == 500 and r.get_json()["reason"] == "misconfigured"
    assert handler.mail_from == []


@pytest.mark.parametrize("value", [None, "", "prod", "LIVE", "Dev", "staging"])
def test_unknown_environment_refuses_everything(env, app_client, smtp_server, client_tls, value):
    handler, port = smtp_server()
    env(port, ENVIRONMENT=value, RECIPIENT_ALLOWLIST=LOGAN)
    r = post(app_client)
    assert r.status_code == 500
    assert handler.mail_from == []
    assert app_client.get("/health").status_code == 500


def test_live_ignores_allowlist(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port, ENVIRONMENT="live", RECIPIENT_ALLOWLIST=LOGAN)
    assert post(app_client, payload(to=OTHER)).status_code == 200
    assert handler.rcpts == [OTHER]


# =========================================================================== 4. how it sends

def test_sent_message_on_the_wire(env, app_client, smtp_server, client_tls, capsys):
    handler, port = smtp_server()
    env(port)
    r = post(app_client)
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "sent"
    assert body["message_id"].endswith("@earlyalert.me>")
    assert handler.tls_at_mail == [True]
    assert handler.ehlo_names and set(handler.ehlo_names) == {"earlyalert.me"}
    assert handler.authenticated == [False]
    mail_from, rcpts, content = handler.messages[0]
    assert mail_from == "noreply@earlyalert.me"
    assert rcpts == [LOGAN]
    import email
    from email import policy
    parsed = email.message_from_bytes(content, policy=policy.default)
    assert parsed["From"] == "Early Alert <noreply@earlyalert.me>"
    assert parsed["To"] == LOGAN
    assert parsed["Message-ID"] == body["message_id"]
    assert parsed["Subject"] == SUBJECT
    assert parsed.get_content_type() == "text/plain"
    assert parsed.get_content_charset() == "utf-8"
    assert parsed.get_content().rstrip() == BODY
    [line] = send_lines(log_lines(capsys))
    assert line["outcome"] == "sent" and line["message_id"] == body["message_id"]


def test_envelope_sender_is_separate_from_header(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port, ENVELOPE_FROM="early-alert-mail@circlesofsupport.net")
    assert post(app_client).status_code == 200
    mail_from, _, content = handler.messages[0]
    assert mail_from == "early-alert-mail@circlesofsupport.net"
    assert "From: Early Alert <noreply@earlyalert.me>" in content.decode()


def test_ehlo_name_is_configurable(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port, SMTP_EHLO_NAME="circlesofsupport.net")
    assert post(app_client).status_code == 200
    assert set(handler.ehlo_names) == {"circlesofsupport.net"}


@pytest.mark.parametrize("name", ["localhost", "smtp-relay.gmail.com", " "])
def test_generic_ehlo_names_are_misconfiguration(env, name):
    env(25, SMTP_EHLO_NAME=name)
    assert not config.load_config().ok


def test_password_mode_authenticates(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port, SMTP_AUTH_MODE="password", SMTP_USERNAME="relay-user", SMTP_PASSWORD="relay-pass")
    assert post(app_client).status_code == 200
    assert handler.authenticated == [True]


def test_password_mode_wrong_password_fails_without_retry(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port, SMTP_AUTH_MODE="password", SMTP_USERNAME="relay-user", SMTP_PASSWORD="wrong")
    r = post(app_client)
    assert r.status_code == 502
    assert r.get_json()["reason"] == "relay_auth_refused"
    assert handler.mail_from == []


@pytest.mark.parametrize("overrides", [
    {"SMTP_AUTH_MODE": "password"},
    {"SMTP_AUTH_MODE": "password", "SMTP_USERNAME": "u"},
    {"SMTP_AUTH_MODE": ""},
    {"SMTP_AUTH_MODE": "none"},
])
def test_auth_mode_misconfiguration(env, app_client, overrides):
    env(25, **overrides)
    assert post(app_client).status_code == 500


def test_ip_mode_never_sends_auth(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port, SMTP_AUTH_MODE="ip", SMTP_USERNAME="relay-user", SMTP_PASSWORD="relay-pass")
    assert post(app_client).status_code == 200
    assert handler.authenticated == [False]


def test_no_starttls_means_no_send(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server(tls=False)
    env(port)
    r = post(app_client)
    assert r.status_code == 502
    assert r.get_json()["reason"] == "starttls_unavailable"
    assert handler.mail_from == [] and handler.messages == []


def test_untrusted_certificate_means_no_send(env, app_client, smtp_server, monkeypatch):
    handler, port = smtp_server()
    env(port)
    monkeypatch.setattr(main, "TLS_CONTEXT_FACTORY", ssl.create_default_context)
    r = post(app_client)
    assert r.status_code == 502
    assert r.get_json()["reason"] == "tls_certificate_invalid"
    assert handler.mail_from == []


# =========================================================================== 5/6. failures and answers

def test_permanent_rcpt_refusal_no_retry_no_partial(env, app_client, smtp_server, client_tls, capsys):
    handler, port = smtp_server()
    env(port)
    handler.rcpt_script = [250, 550]
    r = post(app_client, payload(to=f"{LOGAN},{OTHER}"))
    assert r.status_code == 502
    body = r.get_json()
    assert body["reason"] == "relay_rcpt_550" and body["smtp_code"] == 550
    assert handler.messages == []            # the accepted recipient got nothing either
    assert len(handler.mail_from) == 1       # one attempt
    [line] = send_lines(log_lines(capsys))
    assert line["outcome"] == "failed" and line["attempts"] == 1
    assert line["smtp_reply"] == "scripted rcpt reply"


def test_transient_refusal_retries_once_and_sends(env, app_client, smtp_server, client_tls, capsys):
    handler, port = smtp_server()
    env(port)
    handler.rcpt_script = [451]
    r = post(app_client)
    assert r.status_code == 200
    assert len(handler.messages) == 1
    [line] = send_lines(log_lines(capsys))
    assert line["attempts"] == 2


def test_transient_twice_fails_after_two_attempts(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port)
    handler.mail_script = [421, 421, 421]
    r = post(app_client)
    assert r.status_code == 502
    assert r.get_json()["reason"] == "relay_mail_421"
    assert len(handler.mail_from) == 2
    assert handler.messages == []


def test_permanent_mail_from_refusal(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port)
    handler.mail_script = [550]
    r = post(app_client)
    assert r.status_code == 502 and r.get_json()["reason"] == "relay_mail_550"
    assert len(handler.mail_from) == 1


def test_data_refusal(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port)
    handler.data_script = [554]
    r = post(app_client)
    assert r.status_code == 502 and r.get_json()["reason"] == "relay_data_554"
    assert len(handler.mail_from) == 1


def test_connection_refused_is_failure(env, app_client, client_tls):
    env(_free_port(), SEND_DEADLINE_SECONDS="5", SMTP_TIMEOUT_SECONDS="1")
    r = post(app_client)
    assert r.status_code == 502
    assert r.get_json()["reason"] == "connection_at_connect"


def test_silent_server_times_out_inside_deadline(env, app_client, client_tls):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    held = []
    stop = threading.Event()

    def accept():
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
                held.append(conn)       # never greet
            except OSError:
                pass
    t = threading.Thread(target=accept, daemon=True)
    t.start()
    try:
        env(listener.getsockname()[1], SEND_DEADLINE_SECONDS="2", SMTP_TIMEOUT_SECONDS="2")
        began = time.monotonic()
        r = post(app_client)
        took = time.monotonic() - began
        assert r.status_code == 504
        assert "timeout" in r.get_json()["reason"]
        assert took < 3.0
    finally:
        stop.set()
        t.join()
        for c in held:
            c.close()
        listener.close()


def test_stall_after_data_is_unknown_and_not_retried(env, app_client, smtp_server, client_tls):
    handler, port = smtp_server()
    env(port, SEND_DEADLINE_SECONDS="2", SMTP_TIMEOUT_SECONDS="2")
    handler.data_delay = 3.0
    began = time.monotonic()
    r = post(app_client)
    assert time.monotonic() - began < 3.0
    assert r.status_code == 504
    assert r.get_json()["reason"] == "unknown_after_data_timeout"
    assert len(handler.mail_from) == 1       # never retried after DATA


def test_default_deadline_is_under_textit_timeout():
    cfg = config.load_config({"ENVIRONMENT": "live", "WEBHOOK_SECRET": "s", "SMTP_AUTH_MODE": "ip"})
    assert cfg.ok and cfg.send_deadline == 12.0 and cfg.smtp_timeout == 5.0


@pytest.mark.parametrize("value", ["14", "15", "0", "-1", "abc"])
def test_deadline_at_or_over_textit_timeout_is_misconfiguration(value):
    cfg = config.load_config({"ENVIRONMENT": "live", "WEBHOOK_SECRET": "s", "SMTP_AUTH_MODE": "ip",
                              "SEND_DEADLINE_SECONDS": value})
    assert not cfg.ok


# =========================================================================== 7. what is logged

def test_logs_never_carry_body_subject_or_address(env, app_client, smtp_server, client_tls, capsys):
    handler, port = smtp_server()
    env(port, ENVIRONMENT="dev", RECIPIENT_ALLOWLIST=LOGAN)
    post(app_client)                                          # sent
    post(app_client, payload(to=OTHER))                       # refused: allowlist
    post(app_client, payload(to="bad address"))               # refused: bad request
    post(app_client, secret="wrong")                          # refused: unauthorized
    handler.rcpt_script = [550]
    post(app_client)                                          # failed
    out = capsys.readouterr().out
    lines = [json.loads(line) for line in out.splitlines() if line.strip()]
    sends = [r for r in lines if r.get("event") == "send_email"]
    assert len(sends) == 5                                    # one line per call
    for needle in (BODY, SUBJECT, "Testperson", "distress", LOGAN, OTHER, "logan.test",
                   "counselor@", SECRET):
        assert needle not in out, needle
    for record in sends:
        assert set(record) <= {"severity", "event", "message", "outcome", "reason", "kind",
                               "environment", "recipient_count", "recipient_domains", "attempts",
                               "duration_ms", "smtp_code", "smtp_reply", "message_id",
                               "http_status"}
        assert record["message"].startswith(("SEND_EMAIL_SENT", "SEND_EMAIL_REFUSED",
                                             "SEND_EMAIL_FAILED"))
        assert record["severity"] == {"sent": "INFO", "refused": "WARNING",
                                      "failed": "ERROR"}[record["outcome"]]
        assert record["environment"] == "dev"
        assert isinstance(record["duration_ms"], int)
    assert [r["outcome"] for r in sends] == ["sent", "refused", "refused", "refused", "failed"]
    assert sends[0]["recipient_domains"] == ["example.org"]
    assert sends[0]["kind"] == "triage_request"


def test_invalid_kind_is_not_logged_verbatim(env, app_client, smtp_server, client_tls, capsys):
    handler, port = smtp_server()
    env(port)
    post(app_client, payload(kind="Jordan Testperson"))
    out = capsys.readouterr().out
    assert "Jordan" not in out
    [line] = send_lines([json.loads(x) for x in out.splitlines() if x.strip()])
    assert line["kind"] is None and line["reason"] == "bad_request_kind"


def test_logline_drops_unknown_fields(capsys):
    import logline
    logline.emit(outcome="sent", reason="sent", body=BODY, subject=SUBJECT, to=LOGAN)
    out = capsys.readouterr().out
    assert BODY not in out and SUBJECT not in out and LOGAN not in out
