# send-email

Cloud Run service our TextIt flows call to send an email, in place of TextIt's own Send Email
step.

TextIt's Send Email step does not tell the flow when a send fails: the flow carries on and
nothing readable records it. A webhook step does have a failure exit, so the flows call this
service instead. It sends the message through our Google Workspace SMTP relay as
`Early Alert <noreply@earlyalert.me>`, answers with success or failure, and logs every call so
failures can be counted and alerted on.

## `POST /send`

Header `X-Webhook-Secret: <WEBHOOK_SECRET>` and a JSON body:

```json
{
  "to": "someone@example.org, someone.else@example.org",
  "subject": "Triage request",
  "body": "Plain-text body.",
  "kind": "triage_request"
}
```

- `to` — one address, a comma- or semicolon-separated list in one string (what a TextIt
  expression produces), or a JSON list. Bare addresses only, 1 to `MAX_RECIPIENTS` (10).
  Duplicates are dropped.
- `subject` — required, up to 500 characters. Line breaks become spaces, so a subject can never
  add a header.
- `body` — required plain text, up to 100,000 characters.
- `kind` — required short name for which email this is (`triage_request`, `it_failure`, …):
  lowercase letters, digits, `_`, `-`, up to 40. It is what the logs and metrics group by.

| Status | `status` / `reason` | Meaning |
|---|---|---|
| 200 | `sent` | The relay accepted the message. `message_id` is returned. |
| 400 | `refused` / `bad_request` | A field is missing or invalid; `field` and `detail` say which. |
| 401 | `refused` / `unauthorized` | Missing or wrong secret. |
| 500 | `refused` / `misconfigured` | The service's own configuration is incomplete. Nothing is sent. |
| 502 | `failed` / `relay_…`, `connection_…`, `starttls_unavailable`, `tls_certificate_invalid` | The relay refused, or could not be reached safely. |
| 504 | `failed` / `…timeout…` | No answer in time. `unknown_after_data_…` means the relay may have the message. |

Anything other than 200 takes the flow's Failure exit.

## `GET /health`

`{"status": "ok", "auth_mode": "ip"|"password"}`, or 500
`misconfigured`. No secrets, no addresses.

## How a send works

- One SMTP connection per call to `SMTP_HOST:SMTP_PORT` (`smtp-relay.gmail.com:587`). We present
  `SMTP_EHLO_NAME` (`earlyalert.me`) and **require STARTTLS**; a server that doesn't offer it gets
  nothing, and the relay's certificate is verified.
- `SMTP_AUTH_MODE=ip`: no SMTP login. The service leaves Google Cloud through a fixed address, and
  the relay rule accepts mail from that address. `SMTP_AUTH_MODE=password`: SMTP login with
  `SMTP_USERNAME` / `SMTP_PASSWORD`.
- Every recipient is accepted by the relay before the message is sent, or none of them get it —
  no partial delivery.
- The header From is `FROM_NAME <FROM_ADDRESS>`; the envelope sender is `ENVELOPE_FROM` (defaults to
  `FROM_ADDRESS`). They are separate on purpose: the relay applies its sender rules to the envelope.
- The whole call is bounded by `SEND_DEADLINE_SECONDS` (12, and it must stay under 14), because
  TextIt gives a webhook 15 seconds. At most two attempts; the second only for a temporary failure
  (a 4xx reply, or a connection problem before the message was handed over) and only with at least
  3 seconds left. A 5xx is final.
- Once the message has been handed over, a lost connection or timeout is reported as a failure
  (`unknown_after_data_…`) and never retried by the service, so it never sends a message twice on its
  own and never reports an unknown outcome as sent.

## Logs and the failure count

Each call writes one JSON line: `event=send_email`, `outcome` (`sent` / `refused` / `failed`),
`reason`, `kind`, `recipient_count`, `recipient_domains` (domains only), `attempts`,
`duration_ms`, `smtp_code`, `smtp_reply` (the relay's own reply text), `message_id`, `http_status`,
and a `message` starting `SEND_EMAIL_SENT`, `SEND_EMAIL_REFUSED` or `SEND_EMAIL_FAILED`. Severity is
INFO / WARNING / ERROR. **The body, the subject and full addresses are never logged.**

A log-based metric on these lines, labelled by `outcome` and `kind`, is the
failure count our alerting watches. `message_id` finds the message in the Admin console's Email
Log Search.

## Testing a flow against it

There is one service. A new or changed email is exercised from a DRAFT flow addressed only to
ourselves, and reaches counselors only when that flow is promoted to LIVE — the same review that
governs every flow change. The service doesn't need to know which flow is calling it.

## Configuration

| Variable | Default | |
|---|---|---|
| `WEBHOOK_SECRET` | — | required; from Secret Manager |
| `SMTP_AUTH_MODE` | — | `ip` or `password`; required |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | — | `password` mode only; the password from Secret Manager |
| `SMTP_HOST` / `SMTP_PORT` | `smtp-relay.gmail.com` / `587` | |
| `SMTP_EHLO_NAME` | `earlyalert.me` | must be one of our domains |
| `FROM_NAME` / `FROM_ADDRESS` | `Early Alert` / `noreply@earlyalert.me` | header From |
| `ENVELOPE_FROM` | `FROM_ADDRESS` | envelope sender |
| `MAX_RECIPIENTS` | `10` | 1–100 |
| `SEND_DEADLINE_SECONDS` | `12` | must be under 14 |
| `SMTP_TIMEOUT_SECONDS` | `5` | per SMTP step, within the deadline |

Secrets never live in this repository. They reach the container from Secret Manager
(`gcloud run services update --set-secrets`).

## Build, deploy, test

Pushes to `main` build and deploy `send-email` through its Cloud Build trigger (the trigger runs
its own inline build; `cloudbuild.yaml` is kept for structure and manual builds). Settings and the
secret live on the Cloud Run service, not here.

```
pip install -r requirements-dev.txt
python -m pytest -q tests
```

The tests run a real SMTP server on 127.0.0.1 with STARTTLS on a throwaway certificate; nothing
leaves the machine.
