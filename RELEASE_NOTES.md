Changes on top of the original plugin ([phannhat17/CTFd-Docker-Plugin](https://github.com/phannhat17/CTFd-Docker-Plugin)):

## Added

- **Per-challenge Linux capabilities control**: challenges drop ALL Docker capabilities by default and can re-add only what the image needs, chosen from a checkbox grid in the challenge create/update forms. The selection is enforced server-side against a whitelist — anything else is dropped and logged. A `no-new-privileges` toggle is included (on by default).
- **CI pipeline**: Python and JavaScript sources are validated on every push and pull request.
- **Release pipeline**: tagged versions (`v*`) are validated, packaged and published automatically as a GitHub Release with the `containers.zip` asset — already wrapped in the `containers/` folder, so it extracts straight into `CTFd/plugins/` with no renaming.

## Fixed

- **Importing a CTFd export backup** containing container challenge data no longer breaks: timestamps that arrive as strings from the import are now safely converted back to datetimes (`SafeDateTime` column type).
- **Dynamic scoring fields** (`initial`/`decay`/`minimum`) are correctly mapped for container challenges, fixing the capabilities-era database mismatch.

## Installation

1. Download `containers.zip` below and extract it into `CTFd/plugins/`
2. Mount the Docker socket into the CTFd container (see README)
3. Enable Redis keyspace notifications: `redis-server --notify-keyspace-events Ex`
4. Configure the plugin under **Admin → Containers → Settings**
