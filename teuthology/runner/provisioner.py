import datetime
import logging
import random
import socket
import paramiko

from typing import Dict, List, Optional, Union
from dataclasses import dataclass, asdict

from teuthology import misc
from teuthology.config import config
from teuthology.provision import maas

log = logging.getLogger(__name__)


@dataclass
class MockNode:
    """Represents a mock node/machine in the lock system."""
    name: str
    locked: bool = False
    locked_by: Optional[str] = None
    locked_since: Optional[str] = None
    description: Optional[str] = None
    is_vm: bool = False
    machine_type: str = ""
    ssh_pub_key: str = ""
    up: bool = True
    os_type: str = "ubuntu"
    os_version: str = "22.04"
    arch: str = "x86_64"
    provisioner: str = "mock"

    def to_dict(self) -> dict:
        """Convert to dictionary matching lock server response format."""
        data = asdict(self)
        # Add timestamp if locked
        if self.locked and not self.locked_since:
            data['locked_since'] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
        return data

def get_ssh_pub_key(name: str) -> str:
    """Retrieve the SSH public key using socket.

    :param name: Node name

    :returns: SSH public key string.
    """
    hostname = misc.canonicalize_hostname(name, user=None)
    try:
        timeout = 5.0
        log.debug(f"Fetching SSH public key for {hostname}")
        sock = socket.create_connection((hostname, 22), timeout)
        try:
            transport = paramiko.Transport(sock)
            try:
                transport.start_client(timeout=timeout)
                key = transport.get_remote_server_key()
                if key is None:
                    log.info(f"No host key retrieved for {hostname}")
                    return ""
                return f"{key.get_name()} {key.get_base64()}"
            except Exception as e:
                log.error("Error during SSH transport for %s: %s", hostname, e)
                return ""
            finally:
                transport.close()
        except Exception as e:
            log.error("Error creating SSH transport for %s: %s", hostname, e)
            return ""
        finally:
            sock.close()
    except Exception as e:
        log.error("Could not fetch SSH public key for %s: %s", hostname, e)
        return ""


def get_mass_nodes():
    """Fetch and parse config.maas['machine_types']

    :returns: The list of MAAS-configured machine types. An empty list if MAAS is
              not configured.
    """
    maas_conf = config.get("maas", dict())
    if not maas_conf:
        return []

    types = maas_conf.get("machine_types", "")
    if not isinstance(types, list):
        types = types.split(',')

    log.debug(f"MAAS machine types: {types}")
    nodes = []
    for _type in types:
        log.debug(f"MAAS machine type configured: {_type}")
        for node in maas_conf.get("nodes", {}).get(_type, []):
            log.debug(f"Processing Node: {node}")
            nodes.append(
                MockNode(
                    name=node,
                    locked=False,
                    locked_by=maas_conf.get("owner", "unknown"),
                    description=None,
                    is_vm=False,
                    machine_type=_type,
                    up=True,
                    os_type="ubuntu",
                    os_version="22.04",
                    arch="x86_64",
                    provisioner="maas",
                )
            )
    return nodes


class Provisioner:
    """Mock implementation of teuthology provisioner operations"""

    _instance: Optional["Provisioner"] = None
    _initialized: bool = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, machine_type: str = ""):
        """Initialize mock provisioner system (singleton).

        :param machine_type: The machine type to filter nodes.
        """
        if getattr(self, "_initialized", False):
            return

        self.machine_type = machine_type
        self.nodes: Dict[str, MockNode] = self._get_nodes_from_config()

        log.info(f"Initialized Provisioner with {len(self.nodes)} nodes.")
        self._initialized = True

    def _get_nodes_from_config(self):
        """Generate sample nodes for testing."""
        nodes = {}
        for node in get_mass_nodes():
            if node.machine_type != self.machine_type:
                continue

            nodes[node.name] = node
        return nodes

    def list_nodes(
        self,
        keyed_by_name: bool = False,
        tries: int = 10, 
        **kwargs
    ) -> Union[List[dict], Dict[str, dict]]:
        """List all locks, optionally filtered by criteria.

        :param keyed_by_name: Return dict keyed by node name instead of list
        :param tries: Number of retry attempts (kept for compatibility)
        :param kwargs: Filter criteria (locked, machine_type, is_vm, up, etc.)

        :returns: List of node dicts or dict keyed by name
        """
        # Debug
        log.info("Mocking 'list_locks' method ....")

        # Start with all nodes
        results = list(self.nodes.values())

        # Apply filters
        for key, value in kwargs.items():
            log.debug(f"Applying filter: {key}={value}")
            if key == "locked":
                value = bool(int(value)) if isinstance(value, str) else bool(value)
                results = [n for n in results if n.locked == value]
            elif key == "is_vm":
                value = bool(int(value)) if isinstance(value, str) else bool(value)
                results = [n for n in results if n.is_vm == value]
            elif key == "up":
                value = bool(int(value)) if isinstance(value, str) else bool(value)
                results = [n for n in results if n.up == value]
            elif key == "locked_by":
                results = [n for n in results if n.locked_by == value]
            elif key == "os_type":
                results = [n for n in results if n.os_type == value]

        log.debug(f"list_nodes returned {len(results)} nodes with filters: {kwargs}")

        # Convert to dict format
        result_dicts = [node.to_dict() for node in results]

        if keyed_by_name:
            return {node["name"]: node for node in result_dicts}
        return result_dicts

    def lock_node(self, name: str, owner: str = "", description: str = "") -> bool:
        """Lock a node.

        :param name: Node name
        :param owner: Owner locking the node
        :param description: Optional description

        :returns: True if successful, False otherwise
        """
        node = self.nodes.get(name)
        if not node:
            log.error(f"Node '{name}' not found.")
            return False
        if node.locked:
            log.error(f"Node '{name}' is already locked.")
            return False

        node.locked = True
        if owner:
            node.locked_by = owner
        if description:
            node.description = description
        log.info(f"Node '{name}' locked by '{owner}'.")
        return True

    def unlock_node(self, name: str) -> bool:
        """Unlock a node.

        :param name: Node name

        :returns: True if successful, False otherwise
        """
        node = self.nodes.get(name)
        if not node:
            log.error(f"Node '{name}' not found.")
            return False
        if not node.locked:
            log.error(f"Node '{name}' is not locked.")
            return False

        node.locked = False
        node.locked_by = None
        node.description = None
        log.info(f"Node '{name}' unlocked.")
        return True

    def lock_many_nodes(
        self,
        count: int,
        owner: str = "",
        description: str = "",
        **kwargs
    ) -> List[str]:
        """Lock multiple nodes matching criteria.

        :param count: Number of nodes to lock
        :param owner: Owner locking the nodes
        :param description: Optional description
        :param kwargs: Filter criteria (locked, machine_type, is_vm, up, etc.)

        :returns: List of locked node names
        """
        available_nodes = self.list_nodes(locked=False, **kwargs)
        if len(available_nodes) < count:
            log.error(
                f"Not enough available nodes to lock. Requested: {count}, "
                f"Available: {len(available_nodes)}"
            )
            return []

        to_lock = random.sample(available_nodes, count)
        locked_names = []
        for node in to_lock:
            if self.lock_node(node.get("name"), owner, description):
                locked_names.append(node.get("name"))

        log.info(f"Locked nodes: {locked_names}")
        return locked_names

    def reimage_node(self, name: str, os_type: str, os_version: str) -> bool:
        """Reimage a node.

        :param name: Node name
        :param os_type: OS type to reimage with
        :param os_version: OS version to reimage with

        :returns: True if successful, False otherwise
        """
        node = self.nodes.get(name)
        if not node:
            log.error(f"Node '{name}' not found.")
            return False

        if not node.locked:
            log.error(f"Node '{name}' is not locked; cannot reimage.")
            return False

        prov = None
        if node.provisioner == "maas":
            prov = maas.MAAS(name, os_type, os_version)
        else:
            log.error(f"Node '{name}' has unknown provisioner '{node.provisioner}'.")
            return False

        try:
            prov.create()
            node.up = True
            node.os_type = os_type
            node.os_version = os_version
            node.ssh_pub_key = get_ssh_pub_key(name)
            return True
        except Exception:
            node.up = False
            log.info(f"Failed to reimage node '{name}'.")
            raise

        return False

    def get_node_public_key(self, name: str) -> str:
        """Get the SSH public key for a node.

        :param name: Node name

        :returns: SSH public key string
        """
        node = self.nodes.get(name)
        if not node:
            log.error(f"Node '{name}' not found.")
            return ""

        return node.ssh_pub_key

    def get_canonicalize_hostname(self, name: str) -> str:
        """Get the canonical hostname for a node.

        :param name: Node name

        :returns: Canonical hostname string
        """
        return misc.canonicalize_hostname(name, user=None)
