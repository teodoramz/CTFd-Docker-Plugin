# CTFd Docker Container Challenge Plugin

A comprehensive CTFd plugin that enables dynamic Docker container challenges with advanced features including anti-cheat detection, automatic flag generation, dynamic scoring, and bulk import capabilities.

## Features

### Container Management
- **Dynamic Container Spawning**: Each team/user gets their own isolated Docker container
- **Automatic Lifecycle Management**: Containers auto-expire after configurable timeout
- **Startup Verification**: A container that crashes right after start fails provisioning with its log lines instead of being shown to the player
- **Self-Healing**: Every minute the plugin reconciles the database with Docker — dead containers are cleaned up, orphaned containers are removed, stuck instances are recovered
- **Player Controls**: Fetch / Extend / **Restart** / Terminate buttons on the challenge page, with copy-to-clipboard for connection commands
- **Board Indicator**: Challenge tiles with a running instance get a colored outline + pulsing dot on the challenges page
- **Resource Control**: Global limits for CPU, memory and process count, with optional **per-challenge overrides**
- **Provisioning Throttle**: Caps how many containers start simultaneously (protects the Docker host from start-of-CTF stampedes)
- **Port Management**: Automatic port allocation and mapping with Redis locking
- **Custom Naming**: Containers named as `challengename_accountid_uuid` for easy identification
- **Multi-Deployment Safe**: Every container is stamped with a deployment ID, so multiple CTFd instances can share one Docker host
- **Subdomain routing**: Generate subdomain for each WEB challenge. Read more [here](./SUBDOMAIN_INFO.md)

### Security
- **Capabilities Control**: Drop all Docker capabilities by default, add back only whitelisted ones per challenge
- **no-new-privileges**: Enabled by default per challenge
- **Network Isolation**: Hybrid strategy (see Security Considerations below)

### Anti-Cheat System
- **Flag Reuse Detection**: Automatically detects when teams share flags
- **Instant Ban**: Both flag owner and submitter get banned immediately
- **Audit Logging**: Complete trail of all container and flag activities, browsable in the admin panel with filters and CSV export
- **Cheat Dashboard**: Admin view of all detected cheating attempts, with CSV export

### Scoring Options
- **Standard Scoring**: Fixed points per challenge
- **Dynamic Scoring**: Points decay as more teams solve
  - Linear decay: `value = initial - (decay × solves)`
  - Logarithmic decay: Parabolic curve with minimum floor

### Flag Generation
- **Static Flags**: Same flag for all teams (e.g., `CTF{static_flag}`)
- **Random Flags**: Unique per-team flags with pattern (e.g., `CTF{this_is_the_flag_<ran_8>}` -> `CTF{this_is_the_flag_xxxxxxxx}`)
  - `<ran_N>` produces **exactly N** random characters; an anti-collision fingerprint is embedded inside the requested length so two accounts can never receive the same flag
- **Automatic Preview**: Real-time flag pattern preview during challenge creation

### Bulk Import
- **CSV Import**: Import multiple challenges at once, including capabilities and resource limits
- **Format Validation**: Automatic parsing (RFC 4180, quoted commas supported) and error reporting
- **Progress Tracking**: Real-time feedback during import

### Admin Tooling
- **Health Dashboard**: Running/total instances, provisioning errors in the last hour, free ports — with warning banners on critical thresholds
- **Challenge Dry Run**: Test any challenge from the dashboard — spins up an instance and shows connection info, the generated flag and first log lines
- **Image Pull**: Pull Docker images from the settings page without blocking the platform (background pull with status polling)
- **Audit Log**: Filterable event browser (lifecycle, flag submissions, cheat detections) with expandable JSON details
- **Discord Alerts**: Webhook notifications for cheat detections, provisioning errors and infrastructure problems (Docker down, port pool nearly exhausted) with anti-spam cooldowns

### Performance
- **Redis-Based Expiration**: Precise container killing (0-second accuracy)
- **Non-Blocking Operations**: Image pulls run in background threads; missing images fail fast instead of blocking web workers
- **Efficient Port Management**: Thread-safe port allocation
- **Database Optimization**: Indexed queries for fast lookups

## Installation

1. **Download the latest release:**

Download the latest release from [here](https://github.com/phannhat17/CTFd-Docker-Plugin/releases/latest) and extract it to the `plugins` directory of your CTFd installation.

Remember to rename the extracted folder to `containers`.

![](./image-readme/install.png)

2. **Configure Docker socket access:** (Only for local docker)
```yaml
# In docker-compose.yml
  ctfd:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

3. **Enable Redis keyspace notifications:**
```yaml
# In docker-compose.yml
   cache:
      command: redis-server --notify-keyspace-events Ex --appendonly yes
```

## Security Considerations

### ⚠️ CRITICAL: Cookie Theft Prevention - Reported by [j0r1an](https://jorianwoltjer.com/)

**DO NOT host challenges on the same domain as your CTFd platform.**

#### Vulnerable Configuration ❌
```
CTFd Platform:        ctf.example.com
Challenge Containers: ctf.example.com:30000, ctf.example.com:30001, etc.
```

**Why this is dangerous:**
- Browsers send cookies to ALL ports on the same domain
- If any challenge has an RCE vulnerability, attacker controls that port
- Attacker can steal CTFd session cookies from victims who visit the malicious challenge
- Result: Complete account takeover via session hijacking

#### Secure Configuration ✅
```
CTFd Platform:        ctf.example.com
Challenge Containers: challenges.example.com:30000  (separate subdomain)
                      OR 203.0.113.10:30000         (separate IP)
                      OR challenges-ctf.org:30000   (separate domain)
```

**Why this is secure:**
- Cookies are NOT shared between different domains/subdomains
- Even with RCE, attacker cannot access CTFd session cookies
- Users remain protected from session hijacking

### 🛡️ Container Network Isolation (Hybrid Strategy)

This plugin implements a **Hybrid Network Isolation** strategy to balance security and functionality:

1.  **Host:Port Challenges (Web/TCP)**:
    *   **Network**: `ctfd-isolated`
    *   **Isolation**: **Strict** (`com.docker.network.bridge.enable_icc=false`)
    *   **Effect**: Containers are isolated at Layer 2. They cannot communicate with each other (no ping, no connect). They can still access the internet via the gateway.

2.  **Subdomain Routing (Only affect Web Challenges)**:
    *   **Network**: `ctfd-challenges` (or configured value)
    *   **Isolation**: **Standard** (`enable_icc=true`)
    *   **Effect**: Web challenge containers share a network to allow the Traefik reverse proxy to route traffic. Sibling isolation is *not* enforced at the Docker network level (Traefik requirement).

3.  **Infrastructure Protection**:
    *   The CTFd main container is NOT attached to `ctfd-isolated`.
    *   It generally should not be attached to `ctfd-challenges` either (except for specific specialized setups, but `internal` network is preferred for DB access).
    *   Challenge containers cannot access the CTFd database or Redis directly.

### 🔒 Container Hardening (per challenge)

Every challenge container starts with:
- **All capabilities dropped** (`cap_drop=ALL`) — re-add only what the image needs, from a server-side whitelist
- **no-new-privileges** security option
- **Memory / CPU / PIDs limits** (global defaults, per-challenge overrides)

Typical SSH challenge capabilities: `CHOWN,SETUID,SETGID,SYS_CHROOT,AUDIT_WRITE`. Unknown or non-whitelisted capabilities are silently dropped and logged.

## Configuration

Access admin panel: **Admin → Plugin → Containers → Settings**

![](./image-readme/settings.png)

### Global Settings
- **Docker Connection Type**:
   - Local Docker: Auto connect with `unix://var/run/docker.sock` (must be add volumes at step 1 on Installation section)
   - Remote SSH: set hostname, port, user, key and add the target server public key to know hosts file
   ![](./image-readme/sshconfig.png)
- **Connection Hostname**: **CRITICAL - Set to separate domain/IP** (see Security above)
- **Container Timeout**: Minutes before auto-expiration (default: 60)
- **Max Renewals**: How many times users can extend (default: 3)
- **Port Range**: Starting port for container mapping (default: 30000)
- **Max Concurrent Containers (per User/Team)**: default 3
- **Max Simultaneous Provisions (global)**: how many containers the platform starts at once (default: 4); extra requests get a "try again in a few seconds" message
- **Resource Limits** (global defaults, can be overridden per challenge):
  - Memory: Default `512m`
  - CPU: Default `0.5` cores
  - PIDs: Default `100` processes
- **Discord Webhook**: alerts for cheat detections, provisioning errors and infrastructure problems

### Pulling Images

Challenge images must be present on the Docker host **before** instances can start (images are deliberately not pulled during instance creation — a pull inside a web request would freeze the platform). Use the **Pull Docker Image** card on the Settings page: the pull runs in the background and the page polls its status.

![ss_1](./image-readme/ss_1.png)

## Creating Challenges

### Via Admin UI
![alt text](./image-readme/create.png)

1. **Go to:** Admin → Challenges → Create Challenge → Container
2. **Fill in basic info:**
   - Name, Category, Description
   - State (visible/hidden)

3. **Configure Docker:**
   - **Image**: Docker image with tag (e.g., `nginx:latest`, `ubuntu:20.04`)
   - **Internal Port**: Port exposed inside container (comma-separated list for multi-port challenges)
   - **Command**: Optional startup command
![alt text](./image-readme/docker.png)

4. **Resource Limits (optional):** per-challenge Memory / CPU / PIDs overrides — leave empty to use the global defaults

5. **Security & Privileges:** drop-all-capabilities toggle, whitelist of capabilities to re-add, no-new-privileges toggle

6. **Set Flag Pattern:**
   - Static: `CTF{my_static_flag}`
   - Random: `CTF{prefix_<ran_16>_suffix}`: `<ran_N>` generates exactly N random characters
![](./image-readme/flag.png)

7. **Choose Scoring:**
   - **Standard**: Fixed points
   - **Dynamic**: Initial value, decay rate, minimum value, decay function
![alt text](./image-readme/score.png)

### Via CSV Import

1. **Go to:** Admin → Containers → Import

![alt text](./image-readme/import.png)

2. **Prepare CSV file** with these columns:

#### Example CSV

```csv
name,category,description,image,internal_port,internal_ports,command,connection_type,connection_info,capabilities,drop_all_caps,no_new_privileges,memory_limit,cpu_limit,flag_pattern,scoring_type,value,initial,decay,minimum,decay_function,state
Web Challenge,Web,Find the flag in web app,nginx:latest,80,,,http,Access via browser,,true,true,,,CTF{web_<ran_8>},dynamic,,500,25,100,logarithmic,visible
Simple Challenge,Misc,Easy one,alpine:latest,22,,,tcp,Just connect,,true,true,,,CTF{static_flag},standard,50,,,,standard,visible
SSH Challenge,Pwn,SSH in and get root,ubuntu:20.04,22,,/usr/sbin/sshd -D,ssh,user:ctf pass:ctf,"CHOWN,SETUID,SETGID,SYS_CHROOT,AUDIT_WRITE",true,true,1g,1.0,CTF{<ran_16>},dynamic,,500,20,100,logarithmic,visible
```

**Optional columns** (defaults apply when left empty):

| Column | Description | Default |
|--------|-------------|---------|
| `capabilities` | Comma- or semicolon-separated Linux capabilities to add back (e.g. `"CHOWN,SETUID,SETGID"`). Quote the value if you use commas. Only whitelisted capabilities are applied at container start; unknown ones are dropped with a warning in the logs. | empty |
| `drop_all_caps` | `true`/`false` — drop all default Docker capabilities | `true` |
| `no_new_privileges` | `true`/`false` — set the `no-new-privileges` security option | `true` |
| `internal_ports` | Comma-separated list for multi-port challenges (e.g. `"80,22"`). Quote the value. | empty |
| `memory_limit` | Per-challenge memory override (e.g. `1g`, `256m`) | global setting |
| `cpu_limit` | Per-challenge CPU override (e.g. `1.0`) | global setting |

**⚠️ IMPORTANT:** Docker image MUST include version tag (`:latest`, `:20.04`, etc.) and must already be pulled on the Docker host — images are not pulled automatically at instance start (use the Pull Docker Image card in Settings).

3. **Upload CSV** and wait for import to complete
4. **Check results**: Success/error messages will be displayed

A downloadable template is available on the Import page, and a ready-to-edit `sample_import.csv` ships with the plugin.

### Testing a Challenge (Dry Run)

Before the CTF starts, validate every challenge from **Admin → Containers → Instances**: pick a challenge in the **Test a challenge** card and hit *Run test*. You get the connection info, the generated flag and the first log lines; if the container dies on startup, the test fails with the reason. The test instance runs under your admin account and can be stopped from the instance table.

![ss_2](./image-readme/ss_2.png)

## User Experience

### Requesting Container

1. User clicks **"Fetch Instance"** button on challenge page

![](./image-readme/user.png)

2. Container spawns within seconds
3. Connection info displayed with copy-to-clipboard buttons:
   - HTTP: Browser link
   - TCP: `nc host port`
   - SSH: full `ssh` command

![](./image-readme/http.png)
![](./image-readme/tcp.png)

4. On the challenges board, tiles with a running instance are outlined with a pulsing indicator so players always know where their containers are:

![ss_3](./image-readme/ss_3.png)

### Container Lifecycle

- **Initial Timeout**: Set by admin (default: 60 minutes)
- **Extend**: Users can extend +5 minutes (up to max renewals limit) — added on top of the remaining time
- **Restart**: Stops the current instance and provisions a fresh one with a **new flag**
- **Auto-Expire**: Container killed exactly at expiration time
- **Auto-Stop**: Container killed when flag submitted correctly
- **Crash Recovery**: If a challenge container dies, the platform notices (within a minute, or instantly when the player reopens the challenge) and lets the player fetch a new instance

### Flag Submission

- **Static Flags**: Same for all teams
- **Random Flags**: Unique per team, auto-generated
- **Anti-Cheat**: Reusing another team's flag = instant ban

## Admin Dashboard

Access: **Admin → Containers → Instances**

![alt text](./image-readme/instances.png)

### Features
- **Health Cards**: Running now / total instances / provisioning errors in the last hour / free ports, with warning banners on low ports or high error rate

![ss_4](./image-readme/ss_4.png)

- **Real-time Status**: Running containers
- **Auto-Reload**: Dashboard refreshes every 15 seconds
- **Manual Refresh**: Button to force immediate update
- **Challenge Dry Run**: test any challenge and see its flag/logs (see Creating Challenges above)
- **Container Info**:
  - Challenge name
  - Team/User (clickable links)
  - Connection port
  - Expiry countdown
  - Actions (stop, delete, logs)

### Cheat Detection

![alt text](./image-readme/cheats.png)

Access: **Admin → Containers → Cheat Logs**

Shows all detected flag-sharing attempts with:
- Timestamp
- Challenge name
- Flag hash
- Original owner
- Second submitter
- Automatic ban status
- **Export CSV** button

### Audit Log

Access: **Admin → Containers → Audit Log**

Every event the plugin records — instance lifecycle (created/started/renewed/stopped with reason), flag submissions, cheat detections — browsable with filters (event type, severity, challenge, account), expandable JSON details and CSV export that honours the active filters.

![ss_5](./image-readme/ss_5.png)

## Roadmap

- [x] Support multiple port mapping per image
- [x] Discord webhook notifications
- [x] Per-challenge resource limits
- [x] Challenge dry-run testing from admin
- [x] Audit log browser + CSV exports
- [x] Health dashboard & infrastructure alerts
- [ ] Support docker compose file for challenge creation (multi-container challenges)
- [ ] Prometheus metrics endpoint
- [ ] Multi-host Docker backend (spread instances across several daemons)

## License

See LICENSE file.
