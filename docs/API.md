# API Reference

All endpoints use the CTFd session cookie for authentication. Every `POST`
additionally requires the CSRF header:

```
CSRF-Token: <value of init.csrfNonce>
```

Errors are returned as `{"error": "<message>"}` with an appropriate HTTP
status unless noted otherwise.

## Player API — `/api/v1/containers`

All player endpoints require a logged-in user (`@authed_only`), the CTF to be
running (`@during_ctf_time_only`) and a verified email when verification is
enabled. In team mode the user must belong to a team; instances are owned by
the **account** (team in team mode, user otherwise).

### `POST /request` — fetch (or reuse) an instance
Rate limit: 10/min. Body: `{"challenge_id": <int>}`

Returns the existing instance if one is already running, otherwise creates
one (subject to the per-account concurrent limit and the global provisioning
throttle).

```json
{
  "status": "created | existing",
  "instance_uuid": "…",
  "connection": {
    "host": "…", "port": 30001,
    "ports": {"80": 30001},            // or {"web:80": 30001} in compose mode
    "type": "http", "info": "…",
    "urls": [{"port": 80, "url": "https://…"}]   // subdomain routing only
  },
  "expires_at": 1784184569000,          // ms epoch
  "renewal_count": 0,
  "max_renewals": 3
}
```
Notable errors: `403` when the concurrent-container limit is reached (the
message names the blocking challenges), `500` with a readable message when
the challenge is already solved, the image is missing on the Docker host, or
the platform is saturated (throttle).

### `GET /info/<challenge_id>` — current instance state
Returns `{"status": "not_found"}` when there is no active instance (also
after self-healing a dead container), otherwise the same shape as `/request`
plus `"status": "running" | "provisioning"`.

### `POST /renew` — extend expiry
Rate limit: 10/min. Body: `{"challenge_id": <int>}`

Adds 5 minutes **on top of the remaining time**, up to `max_renewals`.
Returns `{"success": true, "expires_at": <ms>, "renewal_count": <int>}`.

### `POST /stop` — terminate the instance
Rate limit: 10/min. Body: `{"challenge_id": <int>}`

Idempotent: returns `{"success": true, "status": "already_stopped"}` when
there is nothing to stop.

### `POST /restart` — fresh instance, fresh flag
Rate limit: 6/min. Body: `{"challenge_id": <int>}`

Stops the current instance (deleting its temporary flag) and provisions a
new one. Response has the `/request` shape with `"status": "restarted"`.

### `GET /running` — challenges with an active instance
Used by the board indicator. Returns `{"challenge_ids": [3, 7]}`.

## Admin API — `/admin/containers`

All endpoints require an admin session (`@admins_only`).

### Pages (HTML)

| Route | Page |
|-------|------|
| `GET /dashboard` | Instances dashboard (health cards, filters, dry-run card) |
| `GET /settings` | Plugin settings + image pull card |
| `GET /cheats` | Cheat log |
| `GET /audit` | Audit log (filters: `event_type`, `severity`, `account_id`, `challenge_id`, `page`) |
| `GET /import` | CSV import page |

### Instances

| Endpoint | Description |
|----------|-------------|
| `GET /api/instances` | List instances. Query: `status`, `challenge_id`, `account_id`, `limit` (≤500). Returns `{"instances": [...]}` |
| `POST /api/instances/<id>/stop` | Stop one instance |
| `DELETE /api/instances/<id>` | Stop (if running) and delete the DB row |
| `GET /api/instances/<id>/logs` | Last 500 container log lines: `{"logs": "…"}` |
| `POST /api/bulk-delete` | Body `{"instance_ids": [..]}` — stop + delete many |
| `POST /api/bulk/emergency-stop` | Stop **all** running/provisioning instances |
| `POST /api/bulk/cleanup-solved` | Delete all `solved` rows |
| `POST /api/cleanup/expired` | Trigger the expired-instance sweep now |
| `POST /api/cleanup/old` | Trigger the old-row cleanup now |

### Challenge testing (dry run)

`POST /api/challenges/<challenge_id>/test` — provisions an instance under the
admin's own account and returns:

```json
{
  "success": true,
  "instance_uuid": "…",
  "connection": {"host": "…", "port": 30001, "ports": {…}},
  "expires_at": "2026-07-16T08:00:00",
  "flag": "CTF{…}",          // decrypted - admin only
  "logs": "first 20 log lines"
}
```
Returns `500` with a diagnostic when the container dies right after start.

### Docker & images

| Endpoint | Description |
|----------|-------------|
| `GET /api/docker/health` | Connection status + daemon info |
| `GET /api/images` | Image tags available on the Docker host |
| `POST /api/images/pull` | Body `{"image": "name:tag"}` — starts a **background** pull; returns `{"success": true, "status": "pulling", …}`. Untagged references pull `:latest` |
| `GET /api/images/pull-status?image=…` | `{"status": "pulling" \| "done" \| "error" \| "unknown", "detail": "…", "started_at": "…"}` |

### Configuration

| Endpoint | Description |
|----------|-------------|
| `GET /api/config` | All plugin settings as `{"config": {key: value}}` |
| `POST /api/config` | Update settings (JSON object of key/values). `docker_type: "ssh"` additionally writes the SSH key/known_hosts/config files and reconnects |

### Monitoring & exports

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats` | Counters: instances by status, attempts, cheats, docker connectivity |
| `GET /api/cheats` | Recent cheat attempts (JSON) |
| `GET /audit/export` | Audit log as CSV — honours the same filters as the audit page (≤10 000 rows) |
| `GET /cheats/export` | Cheat log as CSV (≤10 000 rows) |
| `POST /api/notifications/test` | Body `{"type": "connection" \| "demo_cheat" \| "demo_error", "url": "…"}` — test the Discord webhook |

### Import

| Endpoint | Description |
|----------|-------------|
| `GET /download-template` | CSV template with example rows |
| `POST /api/import` | Excel upload variant (`.xlsx`/`.xls`, multipart `file`). The import **page** instead parses CSV client-side and creates challenges through CTFd's standard `POST /api/v1/challenges` |
