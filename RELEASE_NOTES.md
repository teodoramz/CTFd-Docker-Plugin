First packaged release of this fork.

## What the plugin provides

- **Container challenge type** for CTFd: each user/team gets an isolated Docker container per challenge, with automatic expiration, renewals and a per-account instance limit
- **Flags**: static or per-team random flags (`CTF{prefix_<ran_N>}`), delivered to the container via the `FLAG` environment variable
- **Anti-cheat**: submitting another team's flag is detected and both accounts are banned automatically, with a dedicated admin log
- **Scoring**: standard or dynamic (linear / logarithmic decay)
- **Security hardening per challenge**: drop-all Linux capabilities with a server-side whitelist for re-added ones, `no-new-privileges`, memory/CPU/PIDs limits
- **Docker connectivity**: local socket or remote host over SSH
- **Subdomain routing** (optional): per-instance subdomains via Traefik + Cloudflare Tunnel instead of host:port
- **Precise expiration** via Redis keyspace notifications, with a polling fallback
- **Admin tooling**: instance dashboard with filters and emergency stop, plugin settings page, cheat log, CSV bulk import of challenges
- Fix for importing CTFd backups that contain container challenge data (datetime handling)

## New in this release

- **CI pipeline**: Python/JavaScript sources validated on every push and pull request
- **Release pipeline**: tagged versions are validated, packaged and published automatically
- **`containers.zip`** asset: already wrapped in the `containers/` folder — extract it straight into `CTFd/plugins/`, no renaming needed

## Installation

1. Download `containers.zip` below and extract it into `CTFd/plugins/`
2. Mount the Docker socket into the CTFd container (see README)
3. Enable Redis keyspace notifications: `redis-server --notify-keyspace-events Ex`
4. Configure the plugin under **Admin → Containers → Settings**
