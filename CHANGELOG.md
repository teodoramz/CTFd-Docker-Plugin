# Changelog

## Unreleased (feature-solve-bugs-and-import)

### Added
- **Docker-compose support for multi-container challenges**: safe compose
  subset (`image`, `command`, `environment`, `ports`, `cap_add`,
  `depends_on`), dedicated per-instance network with service-name DNS,
  dependency-ordered startup, FLAG injection in every service, full cleanup
  of containers + network on stop; UI textarea, CSV column and schema
  auto-migration included
- **Player Restart button**: stops the current instance and provisions a
  fresh one with a new flag (`POST /api/v1/containers/restart`)
- **Challenge board indicator**: tiles with a running instance get a teal
  outline + pulsing dot (`/api/v1/containers/running` + globally injected
  `board.js`), updated instantly on start/stop
- **Copy-to-clipboard** buttons for all connection commands (with plain-http
  fallback)
- **Admin challenge dry run**: spin up a test instance from the dashboard and
  see connection info, the generated flag and first log lines
- **Admin image pull**: non-blocking background pull with status polling from
  the Settings page
- **Audit Log admin page**: filterable event browser with expandable JSON
  details
- **CSV exports** for the audit log (filter-aware) and the cheat log
- **Dashboard health cards**: running/total instances, provisioning errors in
  the last hour, free ports; warning banners on critical thresholds
- **Discord infrastructure alerts**: Docker daemon down, port pool nearly
  exhausted — max one alert per type per 15 minutes
- **Global provisioning throttle** (`max_concurrent_provisions`, default 4):
  protects the Docker host from start-of-CTF stampedes
- **Per-challenge resource limits**: memory/CPU/PIDs overrides in the forms
  and CSV import (empty = global defaults)
- **Startup verification**: containers are watched ~5 s after start; ones
  that exit immediately fail provisioning with their last log lines instead
  of being shown to players
- **Self-healing**: every minute the plugin reconciles DB ⇄ Docker (dead
  containers → instance closed; orphaned containers/networks → removed;
  instances stuck in `pending`/`stopping`/`provisioning` → recovered); the
  info endpoint additionally self-heals on read
- **Per-deployment container label**: multiple CTFd instances can safely
  share one Docker host
- **CSV import**: `capabilities`, `drop_all_caps`, `no_new_privileges`,
  `internal_ports`, `memory_limit`, `cpu_limit`, `compose_yaml` columns;
  RFC 4180 parser (quoted commas/newlines)
- Documentation set: architecture, admin guide, challenge authoring guide,
  API reference, changelog

### Fixed
- **Random flag length**: `<ran_N>` now yields exactly N characters — the
  anti-collision fingerprint is embedded inside the requested length
  (previously appended, so `<ran_8>` silently produced 16 chars)
- **Renew truncation**: extending now adds 5 minutes to the remaining time
  instead of resetting expiry to now+5
- **auto_remove race**: stopping a container that Docker was already removing
  no longer marks the instance as `error`
- **Startup verification race**: `removing` state now counts as a failed
  start; observation window widened 2 s → 5 s
- **Failed stops** no longer fake success and orphan running containers
- **Container name collisions** on retry/leftovers (names now include the
  instance UUID)
- **Platform freezes**: images are no longer pulled inside web requests
  (fail fast + admin pull); Redis expiration listener no longer hard-codes
  DB 0
- `notify_error` TypeError (missing `title`) that masked real provisioning
  errors when a webhook was configured
- Challenge update form silently resetting capabilities to defaults;
  clearing capabilities/limits/compose is now possible
- `create()` type conversions (numeric/boolean form fields)
- Port lock TTL 5 s → 60 s (covers the whole provisioning window)
- Audit log details rendering (compact badges + expandable pretty JSON)
- Concurrent-limit error now names the challenges holding the slots
- Schema auto-migration targets the actual model tables
  (`container_challenge`, not `challenges`)

### Security
- Capability whitelist enforced server-side; `no-new-privileges` and
  drop-all-caps defaults per challenge
- Compose definitions reject `volumes`, `privileged`, `network_mode`,
  `build` and any other unsupported key at save time
- Per-instance networks isolate compose instances of different accounts
