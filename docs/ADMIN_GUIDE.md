# Admin Guide

Operating the plugin before and during a CTF. For installation see the
[README](../README.md); for building challenges see
[CHALLENGE_AUTHORING.md](CHALLENGE_AUTHORING.md).

## Settings — `Admin → Containers → Settings`

| Setting | Meaning | Default |
|---------|---------|---------|
| Docker Connection Type | `local` (socket mount) or `ssh` (remote host; the plugin writes the key, `known_hosts` and an SSH config alias for you) | local |
| Connection Hostname | Host/IP shown to players in connection info. **Must be a different domain/IP than CTFd itself** — see the cookie-theft warning in the README | localhost |
| Container Expiration | Instance lifetime in minutes | 60 |
| Default Max Renewals | How many +5 min extensions a player gets | 3 |
| Port Range | Host ports allocated to instances | 30000–31000 |
| Max Concurrent Containers (per User/Team) | Per-account instance cap; the error message tells players which challenges hold their slots | 3 |
| Max Simultaneous Provisions (global) | How many containers the platform starts at once; extra requests get "try again in a few seconds". Protects the Docker host at CTF start | 4 |
| Max Memory / Max CPU | Global resource defaults (per-challenge overrides win) | 512m / 0.5 |
| Subdomain routing | Traefik-based per-challenge subdomains for web challenges — see [SUBDOMAIN_INFO.md](../SUBDOMAIN_INFO.md) | off |
| Discord Webhook | Receives cheat alerts, provisioning errors and infrastructure alerts; test buttons included | empty |

Settings apply immediately (no restart), except the Docker connection which
reconnects on save.

## Images — pull before the CTF

Instance creation **fails fast** if the image is missing on the Docker host;
nothing is pulled mid-request (a pull inside a web request would freeze
platform workers). Use the **Pull Docker Image** card on the Settings page —
the pull runs in a background thread and the card polls until done/error.
Bulk alternative: `docker pull` directly on the Docker host.

## Dashboard — `Admin → Containers → Instances`

- **Health cards**: Running now · Total instances · Errors in the last hour
  (with successful-start count) · Free ports. A red banner appears when the
  port pool drops under ~10% or errors exceed 5/hour — both mean players are
  about to have a bad time; widen the port range or check images/Docker.
- **Filters**: search by team/user/container id, filter by challenge and
  status. Auto-refreshes every 15 s.
- **Per-instance actions**: view logs, stop, delete (stop + remove the DB
  row). Bulk: select + delete.
- **Emergency Stop**: immediately stops *all* running containers (rows are
  kept as `stopped`). Use when the Docker host is melting.
- **Cleanup solved**: deletes all `solved` rows.

### Testing a challenge (dry run)

The **Test a challenge** card provisions an instance under *your* admin
account and shows the connection info, the **generated flag** and the first
log lines. A container that dies on startup makes the test fail with the
reason (capabilities, bad command, …). The instance is a normal one — stop it
from the table below. Page auto-refresh pauses while a result is displayed.

Run a dry run for every challenge before doors open.

## Audit Log — `Admin → Containers → Audit Log`

Every plugin event, filterable by event type, severity, challenge and
account; details expand into pretty-printed JSON; **Export CSV** honours the
active filters.

Event types:

| Event | Meaning |
|-------|---------|
| `instance_created` / `instance_started` / `instance_renewed` | Lifecycle |
| `instance_stopped_<reason>` | Stop with reason: `manual`, `expired`, `solved`, `restart`, `died` (container vanished), `stale` (stuck-state recovery), `admin`, `admin_delete`, `admin_bulk_delete`, `emergency_stop` |
| `flag_submitted_correct` | Correct solve |
| `flag_reuse_detected` | **Cheat**: someone submitted another account's flag |

## Cheat Log — `Admin → Containers → Cheat Logs`

Fires when a random-mode flag belonging to another account is submitted.
Both accounts (and, in team mode, all their members) are **banned
automatically** and a Discord alert is sent. The submitter only sees
"Incorrect". Review the log and unban via CTFd's user admin if a case turns
out to be innocent. Export CSV available.

## Notifications

With a Discord webhook configured you receive:
- **Cheat detected** — who, which challenge, which flag, whose flag it was
- **Container provisioning errors**
- **Infrastructure alerts** (checked every minute, max one per type per
  15 min): Docker daemon unreachable · port pool ≤ 5% free

## What runs in the background

| Job | Every | Purpose |
|-----|-------|---------|
| Expired cleanup | 1 min | Backup for the precise Redis-based expiry |
| Stale recovery | 1 min | Frees instances stuck in `pending`/`stopping` (5 min) or `provisioning` (10 min) |
| Docker reconcile | 1 min | Marks instances whose container(s) died, removes orphaned containers and per-instance networks |
| Infra check | 1 min | The Discord infrastructure alerts above |
| Old-row cleanup | 1 h | Deletes `stopped` rows >24 h and `error` rows >1 h |

Practical consequences:
- A challenge container that crashes is detected within a minute (or
  instantly when the player reopens the challenge) — the player just fetches
  a new instance.
- Killing containers behind the plugin's back (`docker rm -f …`) is safe;
  reconcile squares the books.

## Multiple CTFd deployments on one Docker host

Each deployment generates a persistent `deployment_id` (stamped on every
container/network as the `ctfd.deployment` label) and only ever manages its
own containers. Containers created by pre-label versions of the plugin are
treated as belonging to the local deployment.

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| "Docker image … is not available on the Docker host" | Pull the image (Settings → Pull Docker Image); tags are required |
| "Container failed to start: … last logs: …" | The image can't run with the challenge's hardening — usually missing capabilities (e.g. nginx needs `CHOWN,SETUID,SETGID,NET_BIND_SERVICE`) or a bad command. The dry run shows the same diagnostics |
| "The platform is starting many containers right now" | Global provision throttle engaged — expected under load; raise *Max Simultaneous Provisions* if the Docker host has headroom |
| "You have reached the maximum number of concurrent containers" | Player hit the per-account cap; the message names the blocking challenges |
| Players report dead connection info | Should self-heal ≤1 min (reconcile) or on modal reopen; if persistent, check `GET /admin/containers/api/docker/health` |
| Expiry not precise (only minute-level) | Redis keyspace notifications unavailable — ensure `--notify-keyspace-events Ex` and that `REDIS_URL` points at the DB the plugin uses; the 1-min poller still guarantees cleanup |
| Port pool exhausted | Widen the range in Settings (applies immediately) |
