"""
Docker Service - Manage Docker containers
"""
import docker
import logging
import threading
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class DockerService:
    """
    Service to interact with Docker daemon
    """
    
    def __init__(self, base_url='unix://var/run/docker.sock', deployment_id=None):
        """
        Initialize Docker client

        Args:
            base_url: Docker daemon URL
                     - Unix socket: 'unix://var/run/docker.sock' (default)
                     - TCP: 'tcp://192.168.1.100:2376'
                     - SSH: 'ssh://user@host:port' or 'ssh://user@host' (default port 22)
            deployment_id: Unique ID of this CTFd deployment. Stamped on every
                     container so multiple CTFd instances can safely share one
                     Docker host without touching each other's containers.
        """
        self.base_url = base_url
        self.deployment_id = deployment_id
        self.client = None
        # Pull-status registry: image name -> {'status', 'detail', 'started_at'}
        # Guarded by _pull_lock because pulls run in background threads.
        self._pull_status = {}
        self._pull_lock = threading.Lock()
        self._connect()
    
    def _connect(self):
        """Connect to Docker daemon - Don't raise exception, just log warning"""
        try:
            # Handle SSH connection
            if self.base_url.startswith('ssh://'):
                logger.info(f"Attempting SSH connection to Docker: {self.base_url}")
                # docker-py supports ssh:// URLs directly
                # Format: ssh://user@host:port or ssh://user@host (default port 22)
                # SSH keys will be used from ~/.ssh/ or SSH agent
                self.client = docker.DockerClient(base_url=self.base_url, timeout=30)
            else:
                # Regular connection (Unix socket or TCP)
                self.client = docker.DockerClient(base_url=self.base_url, timeout=10)
            
            self.client.ping()
            logger.info(f"Connected to Docker daemon at {self.base_url}")
        except Exception as e:
            logger.warning(f"Failed to connect to Docker: {e}")
            logger.warning("Docker connection will be retried when needed. Configure in plugin settings.")
            self.client = None
            # Don't raise - allow plugin to load even if Docker is unavailable
    
    def is_connected(self) -> bool:
        """Check if Docker is connected"""
        if not self.client:
            return False
        try:
            self.client.ping()
            return True
        except:
            return False
    
    def create_container(
        self,
        image: str,
        internal_port: int = None,
        host_port: int = None,
        ports: Dict[str, int] = None,  # New: {'80': 30001, '22': 30002}
        command: str = None,
        environment: Dict[str, str] = None,
        memory_limit: str = "512m",
        cpu_limit: float = 0.5,
        pids_limit: int = 100,
        labels: Dict[str, str] = None,
        name: str = None,
        network: str = None,  # Network to connect for Traefik routing
        use_traefik: bool = False,  # If True, don't expose host port (Traefik handles routing)
        cap_add=None, cap_drop=None, security_opt=None,
        network_aliases: list = None  # DNS aliases on the network (compose service names)
    ) -> Dict[str, Any]:
        """
        Create and start a container
        
        Args:
            image: Docker image name
            internal_port: Port inside container
            host_port: Port on host to expose (ignored if use_traefik=True)
            command: Command to run
            environment: Environment variables
            memory_limit: Memory limit (e.g., "512m", "1g")
            cpu_limit: CPU limit (0.5 = 50% of one core)
            pids_limit: Max number of processes
            labels: Labels for the container
            name: Container name (optional)
            network: Docker network to connect (for Traefik routing)
            use_traefik: If True, use Traefik for routing instead of host port
            cap_add: List of capabilities to add (e.g., ['NET_ADMIN'])
            cap_drop: List of capabilities to drop (e.g., ['ALL'])
            security_opt: List of security options (e.g., ['no-new-privileges'])
        
        Returns:
            {
                'container_id': str,
                'status': str,
                'port': int
            }
        """
        if not self.is_connected():
            raise Exception("Docker is not connected")

        try:
            # Fail fast if the image is not present on the Docker host.
            # docker-py's containers.run() would otherwise pull it inside the
            # web request, blocking a worker for minutes and freezing the platform.
            self.client.images.get(image)

            # ==========================================
            # SECURITY: CAPABILITIES WHITELIST FILTER
            # ==========================================
            ALLOWED_CAPS = {
                'CHOWN', 'SETUID', 'SETGID', 'SYS_CHROOT', 'AUDIT_WRITE',
                'DAC_READ_SEARCH', 'DAC_OVERRIDE', 'NET_ADMIN', 'NET_RAW',
                'NET_BIND_SERVICE', 'SYS_PTRACE', 'SYS_MODULE', 'SYS_TIME',
                'KILL', 'SYS_ADMIN'
            }
            
            safe_cap_add = None
            if cap_add:
                safe_cap_add = []
                for cap in cap_add:
                    clean_cap = str(cap).strip().upper()
                    if clean_cap in ALLOWED_CAPS:
                        safe_cap_add.append(clean_cap)
                    else:
                        logger.warning(f"SECURITY ALERT: Dropped unauthorized Docker capability -> {clean_cap}")
                
                # If the list is empty after filtering, set back to None
                if not safe_cap_add:
                    safe_cap_add = None
            # ==========================================

            # CPU quota calculation
            cpu_period = 100000  # Docker default
            cpu_quota = int(cpu_limit * cpu_period)
            
            # Labels for management
            container_labels = labels or {}
            container_labels.update({
                'ctfd.managed': 'true',
                'ctfd.plugin': 'containers'
            })
            if self.deployment_id:
                container_labels['ctfd.deployment'] = self.deployment_id
            
            # Port mapping - only if not using Traefik
            ports_config = None
            if not use_traefik:
                if ports:
                    # New multi-port mode: ports = {'80': 30001, '22': 30002}
                    ports_config = {}
                    for internal, external in ports.items():
                        ports_config[f'{internal}/tcp'] = external
                elif internal_port:
                    # Legacy single port mode
                    ports_config = {f'{internal_port}/tcp': host_port}
                # else: internal-only container (compose helper service) - no published ports
            
            # Network configuration
            network_arg = network if network else 'bridge'
            # If network is provided, network_mode should be None (or handled by network arg)
            # docker-py run() takes 'network' to connect to a specific network
            
            # Create container
            container = self.client.containers.run(
                image=image,
                name=name,
                command=command,
                detach=True,
                auto_remove=True,  # Auto remove when container stops/fails
                ports=ports_config,
                environment=environment or {},
                mem_limit=memory_limit,
                cpu_quota=cpu_quota,
                cpu_period=cpu_period,
                pids_limit=pids_limit,
                labels=container_labels,
                network=network_arg,
                # Security options
                cap_drop=cap_drop,  # Drop all capabilities
                cap_add=safe_cap_add,  # Add back minimal caps
                security_opt=security_opt  # e.g., ['no-new-privileges']
            )
            
            # Register DNS aliases (compose service names) on the network.
            # containers.run() cannot set aliases directly, so re-attach.
            if network and network_aliases:
                try:
                    net = self.client.networks.get(network)
                    net.disconnect(container)
                    net.connect(container, aliases=network_aliases)
                except Exception as e:
                    logger.warning(f"Failed to set network aliases {network_aliases}: {e}")

            # No need to manually connect if network arg is used
            logger.info(f"Created container {container.id[:12]} from image {image}")

            return {
                'container_id': container.id,
                'status': container.status,
                'port': host_port
            }
            
        except docker.errors.ImageNotFound:
            logger.error(f"Docker image not found: {image}")
            raise Exception(
                f"Docker image '{image}' is not available on the Docker host. "
                f"Pull it first (docker pull {image})"
            )
        except docker.errors.APIError as e:
            logger.error(f"Docker API error: {e}")
            raise Exception(f"Failed to create container: {e}")
        except Exception as e:
            logger.error(f"Unexpected error creating container: {e}")
            raise
    
    def stop_container(self, container_id: str) -> bool:
        """
        Stop and remove a container
        
        Args:
            container_id: Container ID
        
        Returns:
            True if successful, False otherwise
        """
        if not self.is_connected():
            logger.warning("Docker not connected, cannot stop container")
            return False

        try:
            container = self.client.containers.get(container_id)
        except docker.errors.NotFound:
            logger.info(f"Container {container_id[:12]} not found (already removed)")
            return True
        except Exception as e:
            logger.error(f"Error looking up container {container_id[:12]}: {e}")
            return False

        try:
            container.stop(timeout=3)
        except docker.errors.NotFound:
            return True
        except docker.errors.APIError as e:
            # Containers run with auto_remove=True are removed by the daemon as
            # soon as they stop, so 404/409 here means the stop already happened.
            if e.status_code in (404, 409):
                logger.info(f"Container {container_id[:12]} already stopped/being removed")
                return True
            logger.error(f"Error stopping container {container_id[:12]}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error stopping container {container_id[:12]}: {e}")
            return False

        # auto_remove handles removal; explicit remove is a fallback and racing
        # with the daemon's own removal is expected.
        try:
            container.remove(force=True)
        except (docker.errors.NotFound, docker.errors.APIError):
            pass
        except Exception as e:
            logger.warning(f"Error removing container {container_id[:12]}: {e}")

        logger.info(f"Stopped and removed container {container_id[:12]}")
        return True

    def verify_container_startup(self, container_id: str, wait_seconds: float = 5.0, interval: float = 0.5):
        """
        Verify a freshly started container stays up for a short window.

        Catches images/commands that exit immediately (bad entrypoint, missing
        binary, crash on start) BEFORE the user is shown connection info.

        Args:
            container_id: Container ID
            wait_seconds: Observation window
            interval: Poll interval

        Returns:
            (ok: bool, detail: str) - detail contains the last log lines when
            the container died and they could still be read
        """
        if not self.is_connected():
            return True, 'docker unreachable - verification skipped'

        import time
        deadline = time.time() + wait_seconds

        while True:
            try:
                container = self.client.containers.get(container_id)
            except docker.errors.NotFound:
                # auto_remove already deleted it - it exited right after start
                return False, 'container exited immediately and was auto-removed (check image entrypoint/command)'
            except Exception as e:
                logger.warning(f"Startup verification skipped for {container_id[:12]}: {e}")
                return True, f'verification skipped: {e}'

            # 'removing' means it already exited and auto_remove is deleting it
            if container.status in ('exited', 'dead', 'removing'):
                logs = ''
                try:
                    logs = container.logs(tail=20).decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
                detail = f"container status '{container.status}'"
                if logs:
                    detail += f", last logs: {logs}"
                return False, detail

            if time.time() >= deadline:
                return True, container.status

            time.sleep(interval)

    def verify_containers_startup(self, container_ids: list, wait_seconds: float = 5.0, interval: float = 0.5):
        """
        Verify a group of freshly started containers (compose instance) all
        stay up for a short window. Polls the whole group each interval.

        Returns:
            (ok: bool, detail: str)
        """
        if not self.is_connected():
            return True, 'docker unreachable - verification skipped'

        import time
        deadline = time.time() + wait_seconds

        while True:
            for cid in container_ids:
                try:
                    container = self.client.containers.get(cid)
                except docker.errors.NotFound:
                    return False, f'container {cid[:12]} exited immediately and was auto-removed'
                except Exception as e:
                    logger.warning(f"Group startup verification skipped: {e}")
                    return True, f'verification skipped: {e}'

                if container.status in ('exited', 'dead', 'removing'):
                    logs = ''
                    try:
                        logs = container.logs(tail=20).decode('utf-8', errors='ignore').strip()
                    except Exception:
                        pass
                    detail = f"container {cid[:12]} status '{container.status}'"
                    if logs:
                        detail += f", last logs: {logs}"
                    return False, detail

            if time.time() >= deadline:
                return True, 'running'

            time.sleep(interval)

    def list_managed_networks(self):
        """List per-instance networks created by this plugin (label-filtered)"""
        if not self.is_connected():
            return []
        try:
            networks = self.client.networks.list(filters={'label': 'ctfd.managed=true'})
            if not self.deployment_id:
                return [n for n in networks if n.attrs.get('Labels', {}).get('ctfd.instance_uuid')]
            return [
                n for n in networks
                if n.attrs.get('Labels', {}).get('ctfd.instance_uuid')
                and n.attrs.get('Labels', {}).get('ctfd.deployment') in (None, '', self.deployment_id)
            ]
        except Exception as e:
            logger.error(f"Error listing networks: {e}")
            return []

    def container_exists(self, container_id: str) -> Optional[bool]:
        """
        Check if a container still exists on the Docker host

        Returns:
            True if it exists, False if it is gone,
            None if Docker is unreachable (unknown - do not act on it)
        """
        if not self.is_connected():
            return None

        try:
            self.client.containers.get(container_id)
            return True
        except docker.errors.NotFound:
            return False
        except Exception as e:
            logger.error(f"Error checking container {container_id[:12]}: {e}")
            return None
    
    def get_container_status(self, container_id: str) -> Optional[str]:
        """
        Get container status
        
        Returns:
            Status string ('running', 'exited', etc.) or None if not found
        """
        if not self.is_connected():
            return None
        
        try:
            container = self.client.containers.get(container_id)
            return container.status
        except docker.errors.NotFound:
            return None
        except Exception as e:
            logger.error(f"Error getting container status: {e}")
            return None
    
    def is_container_running(self, container_id: str) -> bool:
        """Check if container is running"""
        status = self.get_container_status(container_id)
        return status == 'running'
    
    def list_managed_containers(self):
        """
        List all containers managed by this plugin
        
        Returns:
            List of container objects
        """
        if not self.is_connected():
            return []

        try:
            containers = self.client.containers.list(
                all=True,
                filters={'label': 'ctfd.managed=true'}
            )
            if not self.deployment_id:
                return containers
            # Only containers belonging to THIS deployment. Containers without
            # the label are legacy ones created before the label existed -
            # treat them as ours (pre-label behavior assumed a single deployment).
            return [
                c for c in containers
                if c.labels.get('ctfd.deployment') in (None, '', self.deployment_id)
            ]
        except Exception as e:
            logger.error(f"Error listing containers: {e}")
            return []
    
    def list_images(self):
        """
        List all available Docker images
        
        Returns:
            List of image objects
        """
        if not self.is_connected():
            raise Exception("Docker is not connected")
        
        try:
            images = self.client.images.list()
            return images
        except Exception as e:
            logger.error(f"Failed to list images: {e}")
            raise Exception(f"Failed to list Docker images: {e}")

    def pull_image_async(self, image: str) -> dict:
        """
        Pull a Docker image in a background thread (non-blocking).

        Pulling inside a web request would block a gunicorn worker for
        minutes, so the pull runs in a daemon thread and its progress is
        tracked in self._pull_status (poll it via get_pull_status()).

        Args:
            image: Image name, e.g. 'nginx:latest' or 'nginx'

        Returns:
            The status entry for this image:
            {'status': 'pulling'|'done'|'error', 'detail': str, 'started_at': str}
        """
        if not self.is_connected():
            raise Exception("Docker is not connected")

        with self._pull_lock:
            existing = self._pull_status.get(image)
            if existing and existing['status'] == 'pulling':
                # A pull for this image is already in progress - don't start another
                return dict(existing)

            entry = {
                'status': 'pulling',
                'detail': '',
                'started_at': datetime.utcnow().isoformat()
            }
            self._pull_status[image] = entry

        def _do_pull():
            try:
                # If the image reference has no tag (no ':' after the last '/'),
                # pull 'latest' explicitly - otherwise docker pulls ALL tags.
                if ':' in image.rsplit('/', 1)[-1]:
                    pulled = self.client.images.pull(image)
                else:
                    pulled = self.client.images.pull(image, tag='latest')
                with self._pull_lock:
                    self._pull_status[image] = {
                        'status': 'done',
                        'detail': getattr(pulled, 'id', str(pulled)),
                        'started_at': entry['started_at']
                    }
                logger.info(f"Pulled image {image}")
            except Exception as e:
                with self._pull_lock:
                    self._pull_status[image] = {
                        'status': 'error',
                        'detail': str(e),
                        'started_at': entry['started_at']
                    }
                logger.error(f"Failed to pull image {image}: {e}")

        thread = threading.Thread(target=_do_pull, daemon=True, name=f'image-pull-{image}')
        thread.start()

        return dict(entry)

    def get_pull_status(self, image: str) -> Optional[dict]:
        """
        Get the pull status for an image

        Returns:
            A copy of the status entry, or None if no pull was started
        """
        with self._pull_lock:
            entry = self._pull_status.get(image)
            return dict(entry) if entry else None


    def get_container_logs(self, container_id: str, tail: int = 100) -> Optional[str]:
        """
        Get container logs
        
        Args:
            container_id: Container ID
            tail: Number of lines to return
        
        Returns:
            Logs as string or None
        """
        if not self.is_connected():
            return None
        
        try:
            container = self.client.containers.get(container_id)
            logs = container.logs(tail=tail).decode('utf-8', errors='ignore')
            return logs
        except Exception as e:
            logger.error(f"Error getting container logs: {e}")
            return None
    
    def cleanup_expired_containers(self, instance_uuids: list):
        """
        Cleanup containers không còn trong database
        
        Args:
            instance_uuids: List of valid instance UUIDs from database
        """
        if not self.is_connected():
            return
        
        try:
            containers = self.list_managed_containers()
            for container in containers:
                instance_uuid = container.labels.get('ctfd.instance_uuid')
                if instance_uuid and instance_uuid not in instance_uuids:
                    logger.info(f"Cleaning up orphaned container {container.id[:12]}")
                    try:
                        container.stop(timeout=5)
                        container.remove()
                    except:
                        pass
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def create_network(self, name: str, internal: bool = False, driver: str = 'bridge',
                       options: Dict[str, str] = None, labels: Dict[str, str] = None) -> bool:
        """
        Create a Docker network

        Args:
            name: Network name
            internal: If True, restrict external access
            driver: Network driver (default: bridge)
            options: Driver options (e.g. {'com.docker.network.bridge.enable_icc': 'false'})
            labels: Extra labels (merged over the management labels)

        Returns:
            True if created or already exists, False on error
        """
        if not self.is_connected():
            return False

        try:
            # Check if exists
            try:
                self.client.networks.get(name)
                return True
            except docker.errors.NotFound:
                pass

            network_labels = {'ctfd.managed': 'true'}
            if self.deployment_id:
                network_labels['ctfd.deployment'] = self.deployment_id
            if labels:
                network_labels.update(labels)

            self.client.networks.create(
                name=name,
                driver=driver,
                internal=internal,
                options=options,
                check_duplicate=True,
                labels=network_labels
            )
            logger.info(f"Created network {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create network {name}: {e}")
            return False

    def remove_network(self, name: str) -> bool:
        """
        Remove a Docker network
        
        Args:
            name: Network name
        
        Returns:
            True if removed or not found, False on error
        """
        if not self.is_connected():
            return False
            
        try:
            network = self.client.networks.get(name)
            network.remove()
            logger.info(f"Removed network {name}")
            return True
        except docker.errors.NotFound:
            return True
        except Exception as e:
            # Often fails if network is in use, which is expected during race conditions
            logger.warning(f"Failed to remove network {name} (might be in use): {e}")
            return False
