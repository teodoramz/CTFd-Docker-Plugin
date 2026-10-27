# Challenge Authoring Guide

How to build container challenges — single-image or multi-container — with
correct flags, hardening and limits.

## Two modes

| | Single image | Compose (multi-container) |
|-|--------------|---------------------------|
| Definition | Image + internal port(s) + optional command | `Docker Compose` field (subset, see below) |
| Networking | Shared `ctfd-isolated` network, instances can't see each other | Dedicated per-instance network, services reach each other by name |
| Use when | One process serves the challenge | Web + DB, service + bot, etc. |

## Creating a challenge (UI)

`Admin → Challenges → Create Challenge → type: container`

1. **Basics** — name, category, description, state.
2. **Docker** — image **with tag** (`nginx:latest`, not `nginx`); internal
   port; optional comma-separated `internal_ports` for multi-port
   (e.g. `80,22`); optional command (supports the `{FLAG}` placeholder).
   Or fill **Docker Compose** instead (ignores the fields above).
3. **Resource Limits (optional)** — memory (`512m`, `1g`), CPU (`0.5`),
   PIDs. Empty = the global defaults from Settings.
4. **Security & Privileges** — see below.
5. **Flag pattern** — see below.
6. **Scoring** — standard (fixed) or dynamic:
   - linear: `value = initial − decay × solves`
   - logarithmic: parabolic decay with a `minimum` floor.

## Flag patterns

| Pattern | Result |
|---------|--------|
| `CTF{my_static_flag}` | Same flag for everyone (static mode) |
| `CTF{web_<ran_8>}` | `<ran_N>` → **exactly N** random characters, unique per account |

Random-mode details that matter:
- The flag reaches the container as the `FLAG` environment variable, and any
  `{FLAG}` placeholder in the command/environment is substituted. **Your
  image must place `$FLAG` somewhere the player can capture it.**
- Part of the N characters (half, max 8) is a per-account fingerprint, so two
  teams can never draw the same flag — that would falsely trigger the
  anti-cheat ban. Keep `N ≥ 8` for comfortable entropy.
- Restarting an instance generates a **new** flag; the old one stops
  validating.
- Submitting another team's flag bans **both** teams automatically.

## Security & capabilities

Every container starts with **all capabilities dropped** and
**no-new-privileges** (both toggleable per challenge, keep them on). Add back
only what the image needs — the server enforces this whitelist:

```
AUDIT_WRITE, CHOWN, DAC_OVERRIDE, DAC_READ_SEARCH, KILL, NET_ADMIN,
NET_BIND_SERVICE, NET_RAW, SETGID, SETUID, SYS_ADMIN, SYS_CHROOT,
SYS_MODULE, SYS_PTRACE, SYS_TIME
```

Anything else is silently dropped (and logged). Typical sets:

| Image type | Capabilities |
|------------|-------------|
| nginx / most web servers running as root | `CHOWN,SETUID,SETGID,NET_BIND_SERVICE` |
| OpenSSH server | `CHOWN,SETUID,SETGID,SYS_CHROOT,AUDIT_WRITE` |
| Static binary on port >1024, non-root user | none |

If your container **exits immediately** at start, missing capabilities are
the first thing to check — the dry-run error shows the container's last log
lines (e.g. nginx: `chown(...) failed (1: Operation not permitted)`).

## Multi-container challenges (compose)

Paste into the **Docker Compose** field:

```yaml
services:
  web:
    image: mychal-web:latest
    ports: ["80"]                 # published to the player
    depends_on: [db]
    cap_add: [CHOWN, SETUID, SETGID, NET_BIND_SERVICE]
    environment:
      DB_HOST: db                 # service-name DNS
      APP_FLAG: "{FLAG}"          # substituted per instance
  db:
    image: mariadb:10.11
    environment:
      MYSQL_ROOT_PASSWORD: secret
```

Rules (enforced at save time, with readable errors):
- Allowed service keys: `image` (tagged, required), `command`,
  `environment` (list or mapping), `ports`, `cap_add`, `depends_on`.
  **Everything else is rejected** — `volumes`, `privileged`,
  `network_mode`, `build`, … cannot be used.
- Max **5 services**; at least one must publish a port (`ports:` — the host
  side of `"8080:80"` is ignored, the plugin allocates real host ports).
- `depends_on` controls start order; cycles are rejected.

Per instance the plugin creates a dedicated network (`ctfd-inst-<id>`),
starts services in order with the same hardening/limits as single-image
challenges, injects `FLAG` into **every** service, and removes everything
(containers + network) on stop/expire/solve. Instances of different teams
are fully isolated from each other. Connection info lists ports keyed as
`service:port`.

> Note: subdomain (Traefik) routing applies to single-image web challenges
> only — compose instances are always exposed as host:port.

## CSV bulk import

`Admin → Containers → Import` (template downloadable on the page).

| Column | Notes | Default |
|--------|-------|---------|
| `name`, `category` | required | — |
| `image` | required unless `compose_yaml` is set; must include a tag | — |
| `description` | | empty |
| `internal_port` / `internal_ports` | quote lists: `"80,22"` | 22 |
| `command` | supports `{FLAG}` | empty |
| `connection_type` / `connection_info` | `http`/`tcp`/`ssh`/… + free text | ssh / empty |
| `capabilities` | quoted, comma or semicolon separated | empty |
| `drop_all_caps` / `no_new_privileges` | `true`/`false` | true |
| `memory_limit` / `cpu_limit` | per-challenge overrides | global |
| `compose_yaml` | quoted multi-line YAML (the importer handles newlines inside quotes) | empty |
| `flag_pattern` | `CTF{static}` or `CTF{x_<ran_12>}` | `CTF{flag}` |
| `scoring_type` | `standard` or `dynamic` | standard |
| `value` | standard mode points | 100 |
| `initial` / `decay` / `minimum` / `decay_function` | dynamic mode | 500/20/100/logarithmic |
| `state` | `visible` / `hidden` | visible |

## Test before the CTF

For every challenge run a **dry run** (`Admin → Containers → Instances →
Test a challenge`): you get the connection info, the generated flag and the
first log lines — or a precise failure reason. Then actually connect and
capture the flag once yourself.

## Common pitfalls

- **Image without a tag** → rejected at creation/instance time.
- **Image not pulled on the Docker host** → instance fails fast; pull via
  Settings → Pull Docker Image.
- **Container exits at start** → usually capabilities (see above) or a
  command that terminates; the dry run shows the logs.
- **Flag not in the container** → the plugin only *delivers* `$FLAG`; the
  image must write/serve it (e.g. entrypoint `echo $FLAG > /flag.txt`).
- **Compose service can't reach its sibling** → use the *service name* as
  hostname (`db`), not `localhost`.
- **Web challenge on port 80 as root** → needs `NET_BIND_SERVICE` (binding
  <1024 with capabilities dropped fails even as root).
