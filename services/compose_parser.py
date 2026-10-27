"""
Compose Parser - validates and parses a minimal, security-conscious subset
of docker-compose for multi-container challenges.

Supported per service: image (required, tagged), command, environment
(list or dict), ports (container ports to publish), cap_add, depends_on.
Anything else (volumes, privileged, network_mode, build, ...) is rejected.
"""
import re
import yaml

MAX_SERVICES = 5

ALLOWED_SERVICE_KEYS = {'image', 'command', 'environment', 'ports', 'cap_add', 'depends_on'}

_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$')


class ComposeValidationError(Exception):
    """Compose definition is invalid - message is safe to show to admins"""


def parse_compose(yaml_text: str) -> list:
    """
    Parse and validate a challenge compose definition.

    Args:
        yaml_text: The compose YAML source

    Returns:
        List of service dicts in START ORDER (dependencies first):
        [{'name', 'image', 'command', 'environment': dict,
          'ports': [int], 'cap_add': [str], 'depends_on': [str]}]

    Raises:
        ComposeValidationError with an admin-readable message
    """
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise ComposeValidationError(f"Invalid YAML: {e}")

    if not isinstance(data, dict) or not isinstance(data.get('services'), dict) or not data['services']:
        raise ComposeValidationError("Compose must define a non-empty 'services' mapping")

    top_extra = set(data.keys()) - {'services', 'version'}
    if top_extra:
        raise ComposeValidationError(
            f"Unsupported top-level keys: {', '.join(sorted(str(k) for k in top_extra))} "
            "(only 'services' is supported)"
        )

    services_raw = data['services']
    if len(services_raw) > MAX_SERVICES:
        raise ComposeValidationError(f"Too many services (max {MAX_SERVICES})")

    services = {}
    declaration_order = []
    for name, svc in services_raw.items():
        name = str(name)
        declaration_order.append(name)

        if not _NAME_RE.match(name):
            raise ComposeValidationError(f"Invalid service name: '{name}'")
        if not isinstance(svc, dict):
            raise ComposeValidationError(f"Service '{name}' must be a mapping")

        extra = set(svc.keys()) - ALLOWED_SERVICE_KEYS
        if extra:
            raise ComposeValidationError(
                f"Service '{name}': unsupported keys: {', '.join(sorted(str(k) for k in extra))} "
                f"(allowed: {', '.join(sorted(ALLOWED_SERVICE_KEYS))})"
            )

        image = svc.get('image')
        if not image or not isinstance(image, str):
            raise ComposeValidationError(f"Service '{name}': 'image' is required")
        if ':' not in image.rsplit('/', 1)[-1]:
            raise ComposeValidationError(f"Service '{name}': image must include a tag (e.g. '{image}:latest')")

        # environment: list ("K=V") or mapping
        env = svc.get('environment') or {}
        if isinstance(env, list):
            env_dict = {}
            for item in env:
                if not isinstance(item, str) or '=' not in item:
                    raise ComposeValidationError(
                        f"Service '{name}': environment list entries must look like 'KEY=value'"
                    )
                k, v = item.split('=', 1)
                env_dict[k] = v
            env = env_dict
        elif not isinstance(env, dict):
            raise ComposeValidationError(f"Service '{name}': environment must be a list or mapping")
        env = {str(k): ('' if v is None else str(v)) for k, v in env.items()}

        # ports: publish container ports; accept 80 / "80" / "8080:80" (host side ignored,
        # the plugin allocates host ports itself)
        ports = []
        for p in svc.get('ports') or []:
            port_str = str(p).split(':')[-1].split('/')[0].strip()
            if not port_str.isdigit() or not (0 < int(port_str) < 65536):
                raise ComposeValidationError(f"Service '{name}': invalid port '{p}'")
            ports.append(int(port_str))

        cap_add = svc.get('cap_add') or []
        if not isinstance(cap_add, list):
            raise ComposeValidationError(f"Service '{name}': cap_add must be a list")
        cap_add = [str(c).strip().upper() for c in cap_add if str(c).strip()]

        depends = svc.get('depends_on') or []
        if isinstance(depends, dict):
            # long form with conditions - we only honour the ordering
            depends = list(depends.keys())
        if not isinstance(depends, list):
            raise ComposeValidationError(f"Service '{name}': depends_on must be a list")
        depends = [str(d) for d in depends]

        command = svc.get('command')
        if command is not None and not isinstance(command, (str, list)):
            raise ComposeValidationError(f"Service '{name}': command must be a string or list")
        if isinstance(command, list):
            command = [str(c) for c in command]

        services[name] = {
            'name': name,
            'image': image,
            'command': command,
            'environment': env,
            'ports': ports,
            'cap_add': cap_add,
            'depends_on': depends,
        }

    # depends_on references must exist
    for svc in services.values():
        for dep in svc['depends_on']:
            if dep not in services:
                raise ComposeValidationError(
                    f"Service '{svc['name']}' depends on unknown service '{dep}'"
                )

    # topological sort (dependencies first), stable on declaration order
    ordered = []
    resolved = set()
    remaining = dict(services)
    while remaining:
        ready = [n for n in declaration_order
                 if n in remaining and all(d in resolved for d in remaining[n]['depends_on'])]
        if not ready:
            raise ComposeValidationError("Circular depends_on detected")
        for n in ready:
            ordered.append(remaining.pop(n))
            resolved.add(n)

    if not any(s['ports'] for s in ordered):
        raise ComposeValidationError(
            "At least one service must publish a port via 'ports' (the player entry point)"
        )

    return ordered


def get_entry_service(services: list) -> dict:
    """First service (in declaration/start order) that publishes a port"""
    return next(s for s in services if s['ports'])
