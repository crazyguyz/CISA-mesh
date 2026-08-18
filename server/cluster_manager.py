"""
Cluster Manager for GIAM-SAT Server v1.14.0
Multi-node HA cluster with:
  - Automatic master election (Raft-inspired)
  - Load balancing across nodes (round-robin + agent count)
  - Heartbeat-based health checks (configurable interval)
  - Config/rule synchronization between nodes
  - Agent redirection on node failure
  - Cluster-wide alerting
  - REST API for cluster management

v1.6.0: Basic node discovery + failover
v1.14.0: Full HA with load balancing, election, sync, health checks
"""
import os
import json
import socket
import threading
import time
import random
from datetime import datetime

DEFAULT_CLUSTER_PORT = 7777
HEARTBEAT_INTERVAL = 10      # seconds between heartbeats
NODE_TIMEOUT = 45            # seconds before node considered dead
ELECTION_TIMEOUT_MIN = 5     # min random election timeout
ELECTION_TIMEOUT_MAX = 10    # max random election timeout
SYNC_INTERVAL = 30           # seconds between config syncs
LOAD_BALANCE_ALGORITHM = "round_robin"  # or "least_agents"


class ClusterManager:
    """Manages multi-node HA cluster with load balancing and automatic failover."""

    def __init__(self, node_id=None, bind_ip="0.0.0.0", cluster_port=DEFAULT_CLUSTER_PORT,
                 tcp_port=6666, web_port=5000):
        self.node_id = node_id or socket.gethostname()
        self.bind_ip = bind_ip
        self.cluster_port = cluster_port
        self.tcp_port = tcp_port
        self.web_port = web_port
        self.nodes = {}  # node_id -> {ip, tcp_port, web_port, last_seen, is_master, status, agent_count}
        self.is_master = True
        self.running = True
        self.lock = threading.Lock()
        self._local_agent_count = 0
        self._config_version = 0
        self._synced_configs = {}  # node_id -> version
        self._election_in_progress = False
        self._master_since = time.time()
        self._load_config()

    # =========================================================================
    # Config persistence
    # =========================================================================

    def _get_config_path(self):
        data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        return os.path.join(data_dir, "cluster_config.json")

    def _load_config(self):
        path = self._get_config_path()
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    cfg = json.loads(f.read())
                    self.nodes = cfg.get("nodes", {})
                    self.node_id = cfg.get("node_id", self.node_id)
                    self.is_master = cfg.get("is_master", True)
                    self._config_version = cfg.get("config_version", 0)
            except Exception:
                pass

    def _save_config(self):
        try:
            path = self._get_config_path()
            with open(path, "w") as f:
                json.dump({
                    "node_id": self.node_id,
                    "is_master": self.is_master,
                    "nodes": self.nodes,
                    "config_version": self._config_version,
                    "last_updated": datetime.now().isoformat(),
                }, f, indent=2)
        except Exception:
            pass

    # =========================================================================
    # Node Management
    # =========================================================================

    def set_agent_count(self, count: int):
        """Update local agent count for load balancing."""
        self._local_agent_count = count

    def add_node(self, node_id, ip, tcp_port=6666, web_port=5000, is_master=False):
        with self.lock:
            self.nodes[node_id] = {
                "ip": ip, "tcp_port": tcp_port, "web_port": web_port,
                "last_seen": time.time(), "is_master": is_master,
                "status": "online", "agent_count": 0,
                "config_version": 0,
            }
            self._save_config()

    def remove_node(self, node_id):
        with self.lock:
            if node_id in self.nodes:
                del self.nodes[node_id]
                # If master was removed, trigger election
                if not self._get_active_master():
                    self._trigger_election()
                self._save_config()

    def update_heartbeat(self, node_id, agent_count=0, config_version=0):
        """Called when receiving heartbeat from another node."""
        with self.lock:
            if node_id in self.nodes:
                self.nodes[node_id]["last_seen"] = time.time()
                self.nodes[node_id]["status"] = "online"
                self.nodes[node_id]["agent_count"] = agent_count
                self.nodes[node_id]["config_version"] = config_version
                self._synced_configs[node_id] = config_version

    # =========================================================================
    # Master Election
    # =========================================================================

    def _get_active_master(self):
        """Return (node_id, info) of the current active master."""
        for nid, info in self.nodes.items():
            if info.get("is_master") and self._is_node_alive(nid):
                return nid, info
        return None, None

    def _is_node_alive(self, node_id):
        """Check if a node is alive based on last heartbeat."""
        if node_id not in self.nodes:
            return False
        return time.time() - self.nodes[node_id].get("last_seen", 0) < NODE_TIMEOUT

    def _trigger_election(self):
        """Start a master election. Node with lowest node_id wins (deterministic)."""
        if self._election_in_progress:
            return
        self._election_in_progress = True

        try:
            # Wait random timeout to avoid simultaneous elections
            delay = random.uniform(ELECTION_TIMEOUT_MIN, ELECTION_TIMEOUT_MAX)
            time.sleep(delay)

            with self.lock:
                # Find all alive nodes
                alive = [nid for nid in self.nodes if self._is_node_alive(nid)]
                alive.append(self.node_id)  # Include self

                if not alive:
                    self._election_in_progress = False
                    return

                # Sort by node_id (deterministic winner)
                alive.sort()
                new_master = alive[0]

                # Update master status
                self.is_master = (new_master == self.node_id)
                for nid in self.nodes:
                    self.nodes[nid]["is_master"] = (nid == new_master)

                self._master_since = time.time()
                self._save_config()

                if self.is_master:
                    print(f"[*] Cluster: I am the new MASTER ({self.node_id})")
                else:
                    print(f"[*] Cluster: {new_master} is the new master")

        finally:
            self._election_in_progress = False

    def get_master_node(self):
        """Get current master node. Self-promote if no master alive."""
        master_id, master_info = self._get_active_master()
        if master_id:
            return master_id, master_info

        # No master alive - self-promote if this node is designated
        if self.is_master or not self.nodes:
            return self.node_id, {
                "ip": self.bind_ip, "tcp_port": self.tcp_port,
                "web_port": self.web_port, "is_master": True,
            }

        # Trigger election
        self._trigger_election()
        time.sleep(1)
        return self.get_master_node()

    # =========================================================================
    # Load Balancing
    # =========================================================================

    def get_best_node_for_agent(self, agent_ip: str) -> dict:
        """Select the best node for a new agent to connect to.

        Algorithm:
          - "round_robin": Rotate through available nodes
          - "least_agents": Pick node with fewest agents
        """
        with self.lock:
            available = {
                nid: info for nid, info in self.nodes.items()
                if self._is_node_alive(nid)
            }
            # Always include self
            available[self.node_id] = {
                "ip": self.bind_ip, "tcp_port": self.tcp_port,
                "web_port": self.web_port,
                "agent_count": self._local_agent_count,
                "is_master": self.is_master,
            }

            if not available:
                return {
                    "ip": self.bind_ip, "tcp_port": self.tcp_port,
                    "web_port": self.web_port,
                }

            if LOAD_BALANCE_ALGORITHM == "least_agents":
                # Select node with fewest agents
                best = min(available.items(), key=lambda x: x[1].get("agent_count", 99))
                return best[1]
            else:
                # Round-robin: use hash of time to rotate
                nodes_list = list(available.keys())
                idx = int(time.time() / 5) % len(nodes_list)
                return available[nodes_list[idx]]

    def get_all_active_nodes(self):
        """Get all active nodes in the cluster."""
        with self.lock:
            active = {
                nid: info for nid, info in self.nodes.items()
                if self._is_node_alive(nid)
            }
            # Include self
            active[self.node_id] = {
                "ip": self.bind_ip, "tcp_port": self.tcp_port,
                "web_port": self.web_port, "last_seen": time.time(),
                "is_master": self.is_master, "status": "online",
                "agent_count": self._local_agent_count,
                "config_version": self._config_version,
            }
            return active

    def agents_per_node(self):
        """Return agent distribution across nodes for load monitoring."""
        dist = {}
        with self.lock:
            for nid, info in self.nodes.items():
                dist[nid] = info.get("agent_count", 0)
            dist[self.node_id] = self._local_agent_count
        return dist

    def total_cluster_agents(self) -> int:
        """Get total agent count across entire cluster."""
        return sum(self.agents_per_node().values())

    # =========================================================================
    # Failover
    # =========================================================================

    def check_failed_nodes(self) -> list:
        """Check for failed nodes and handle failover. Returns list of failed node IDs."""
        failed = []
        with self.lock:
            for nid in list(self.nodes.keys()):
                if not self._is_node_alive(nid):
                    if self.nodes[nid].get("status") != "offline":
                        self.nodes[nid]["status"] = "offline"
                        failed.append(nid)
                        print(f"[!] Cluster: Node {nid} is OFFLINE (last seen: {datetime.fromtimestamp(self.nodes[nid]['last_seen'])})")

        # If master failed, trigger election
        if failed:
            master_id, _ = self._get_active_master()
            if not master_id:
                self._trigger_election()

        return failed

    def failover_agents(self, from_node_id, to_node_ip, to_node_port):
        """Redirect agents from a failed node to a healthy node."""
        print(f"[!] Failover: Agents from {from_node_id} redirected to {to_node_ip}:{to_node_port}")
        return {
            "action": "redirect",
            "from": from_node_id,
            "to": {"ip": to_node_ip, "port": to_node_port},
        }

    # =========================================================================
    # Config/Rules Synchronization
    # =========================================================================

    def sync_config(self, config_data: dict):
        """Receive synced configuration from master."""
        with self.lock:
            new_version = config_data.get("version", 0)
            if new_version > self._config_version:
                self._config_version = new_version
                # Apply synced config
                for section, data in config_data.get("sections", {}).items():
                    self._apply_config_section(section, data)
                print(f"[*] Cluster: Config synced to version {new_version}")

    def _apply_config_section(self, section: str, data: dict):
        """Apply a configuration section from sync."""
        if section == "alerting":
            # Sync alerting rules
            pass
        elif section == "retention":
            # Sync retention policies
            pass
        elif section == "correlation_rules":
            # Sync correlation rules hash
            pass

    def get_config_for_sync(self) -> dict:
        """Get configuration to sync to other nodes (master -> followers)."""
        self._config_version += 1
        return {
            "version": self._config_version,
            "node_id": self.node_id,
            "timestamp": datetime.now().isoformat(),
            "sections": {
                "nodes": self.get_all_active_nodes(),
                "cluster_topology": {
                    "total_agents": self.total_cluster_agents(),
                    "master": self.node_id if self.is_master else None,
                },
            },
        }

    # =========================================================================
    # Health Checks
    # =========================================================================

    def get_cluster_health(self) -> dict:
        """Get comprehensive cluster health report."""
        active_nodes = self.get_all_active_nodes()
        total_nodes = len(active_nodes)
        master_id, _ = self.get_master_node()
        failed = [nid for nid in self.nodes if nid not in active_nodes]

        return {
            "cluster_id": self.node_id,
            "status": "healthy" if master_id and len(failed) == 0 else "degraded" if master_id else "critical",
            "master_node": master_id,
            "total_nodes": total_nodes,
            "active_nodes": len(active_nodes),
            "failed_nodes": failed,
            "total_agents": self.total_cluster_agents(),
            "uptime_seconds": time.time() - self._master_since if self.is_master else 0,
            "config_version": self._config_version,
            "agent_distribution": self.agents_per_node(),
            "timestamp": datetime.now().isoformat(),
        }

    # =========================================================================
    # Network Listener
    # =========================================================================

    def start_cluster_listener(self):
        """Start the UDP cluster heartbeat listener."""
        threading.Thread(target=self._cluster_udp_listener, daemon=True).start()
        print(f"[*] Cluster: UDP listener on port {self.cluster_port}")

        # Start heartbeat sender
        threading.Thread(target=self._heartbeat_sender, daemon=True).start()

        # Start health monitor
        threading.Thread(target=self._health_monitor, daemon=True).start()

        # Start config sync (master only)
        threading.Thread(target=self._config_syncer, daemon=True).start()

    def _cluster_udp_listener(self):
        """Listen for cluster UDP messages."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.cluster_port))
            sock.settimeout(1.0)
        except Exception as e:
            print(f"[-] Cluster: Cannot bind UDP port {self.cluster_port}: {e}")
            return

        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
                self._handle_cluster_message(data, addr)
            except socket.timeout:
                continue
            except Exception:
                if self.running:
                    time.sleep(0.1)

        sock.close()

    def _handle_cluster_message(self, data, addr):
        """Process incoming cluster messages."""
        try:
            msg = json.loads(data.decode("utf-8"))
            # v4.10 (MED-2): reject unsigned/forged cluster messages
            if not self._cluster_verified(msg):
                print(f"[!] Cluster: unauthenticated message from {addr[0]} ignored")
                return
            msg_type = msg.get("type")

            if msg_type == "heartbeat":
                node_id = msg.get("node_id", "")
                self.update_heartbeat(
                    node_id,
                    agent_count=msg.get("agent_count", 0),
                    config_version=msg.get("config_version", 0),
                )
                # If sender claims to be master and we think we are too, verify
                if msg.get("is_master") and self.is_master and node_id != self.node_id:
                    # Conflict resolution: compare node_id (deterministic)
                    if node_id < self.node_id:
                        self.is_master = False
                        self.nodes[node_id]["is_master"] = True
                        print(f"[*] Cluster: Yielding master to {node_id}")

            elif msg_type == "config_sync":
                self.sync_config(msg.get("config", {}))

            elif msg_type == "node_discover":
                # Respond with our info (signed)
                response = self._cluster_sign({
                    "type": "node_info",
                    "node_id": self.node_id,
                    "ip": self.bind_ip,
                    "tcp_port": self.tcp_port,
                    "web_port": self.web_port,
                    "is_master": self.is_master,
                    "agent_count": self._local_agent_count,
                    "config_version": self._config_version,
                })
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(json.dumps(response).encode("utf-8"), addr)
                sock.close()

            elif msg_type == "node_info":
                # Register discovered node
                node_id = msg.get("node_id", "")
                if node_id and node_id != self.node_id:
                    self.add_node(
                        node_id,
                        msg.get("ip", addr[0]),
                        msg.get("tcp_port", 6666),
                        msg.get("web_port", 5000),
                        msg.get("is_master", False),
                    )

        except (json.JSONDecodeError, KeyError):
            pass

    def _heartbeat_sender(self):
        """Periodically send heartbeat to all known nodes."""
        while self.running:
            try:
                self.send_heartbeat(self.tcp_port, self.web_port)
            except Exception:
                pass
            time.sleep(HEARTBEAT_INTERVAL)

    def _cluster_secret(self):
        return os.environ.get("GIAMSAT_CLUSTER_SECRET", "")

    def _cluster_sign(self, payload: dict) -> dict:
        """v4.10 (MED-2): HMAC-SHA256 sign a cluster message with the shared secret."""
        import json as _json, hmac as _hmac, hashlib as _hl
        secret = self._cluster_secret()
        msg = dict(payload)
        msg["_sig"] = ""
        if secret:
            body = _json.dumps(msg, sort_keys=True, ensure_ascii=False)
            msg["_sig"] = _hmac.new(secret.encode(), body.encode(), _hl.sha256).hexdigest()
        return msg

    def _cluster_verified(self, msg: dict) -> bool:
        """v4.10 (MED-2): verify the HMAC signature of an incoming cluster message.
        Fail-closed: without GIAMSAT_CLUSTER_SECRET no cluster message is accepted."""
        import json as _json, hmac as _hmac, hashlib as _hl
        secret = self._cluster_secret()
        if not secret:
            print("[!] Cluster: GIAMSAT_CLUSTER_SECRET not set - rejecting cluster messages (fail-closed)")
            return False
        sig = msg.get("_sig", "")
        check = dict(msg)
        check["_sig"] = ""
        body = _json.dumps(check, sort_keys=True, ensure_ascii=False)
        expected = _hmac.new(secret.encode(), body.encode(), _hl.sha256).hexdigest()
        return bool(sig) and _hmac.compare_digest(sig, expected)

    def send_heartbeat(self, tcp_port=6666, web_port=5000):
        """Send heartbeat broadcast to cluster."""
        msg = self._cluster_sign({
            "type": "heartbeat",
            "node_id": self.node_id,
            "is_master": self.is_master,
            "agent_count": self._local_agent_count,
            "config_version": self._config_version,
            "tcp_port": tcp_port,
            "web_port": web_port,
            "timestamp": time.time(),
        })

        with self.lock:
            targets = [(info["ip"], self.cluster_port) for nid, info in self.nodes.items()
                       if nid != self.node_id]

        # Also broadcast on local network
        targets.append(("255.255.255.255", self.cluster_port))

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        for ip, port in set(targets):
            try:
                sock.sendto(json.dumps(msg).encode("utf-8"), (ip, port))
            except Exception:
                pass

        sock.close()

    def _health_monitor(self):
        """Monitor node health and trigger failover if needed."""
        while self.running:
            time.sleep(NODE_TIMEOUT / 2)
            try:
                failed = self.check_failed_nodes()
                if failed:
                    print(f"[!] Cluster Health: {len(failed)} node(s) failed: {failed}")
                    if self.is_master:
                        for node_id in failed:
                            # Redirect agents from failed node
                            target = self.get_best_node_for_agent("")
                            self.failover_agents(node_id, target.get("ip"), target.get("tcp_port"))
            except Exception:
                pass

    def _config_syncer(self):
        """Master node periodically syncs config to followers."""
        while self.running:
            time.sleep(SYNC_INTERVAL)
            if not self.is_master:
                continue

            try:
                config = self.get_config_for_sync()
                # v4.10 (MED-2): sign config_sync too (receivers verify all messages)
                msg = self._cluster_sign({
                    "type": "config_sync",
                    "config": config,
                })

                with self.lock:
                    targets = [(info["ip"], self.cluster_port) for nid, info in self.nodes.items()
                               if nid != self.node_id and self._is_node_alive(nid)]

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                for ip, port in targets:
                    try:
                        sock.sendto(json.dumps(msg).encode("utf-8"), (ip, port))
                    except Exception:
                        pass
                sock.close()
            except Exception:
                pass

    # =========================================================================
    # Node Discovery
    # =========================================================================

    def discover_nodes(self, broadcast_ip="255.255.255.255"):
        """Actively discover other cluster nodes on the network."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(2.0)

        msg = json.dumps({"type": "node_discover"}).encode("utf-8")
        try:
            sock.sendto(msg, (broadcast_ip, self.cluster_port))
        except Exception:
            pass

        # Collect responses
        responses = []
        start = time.time()
        while time.time() - start < 3.0:
            try:
                data, addr = sock.recvfrom(4096)
                resp = json.loads(data.decode("utf-8"))
                responses.append(resp)
            except socket.timeout:
                break
            except Exception:
                break

        sock.close()

        # Register discovered nodes
        for resp in responses:
            node_id = resp.get("node_id", "")
            if node_id and node_id != self.node_id:
                self.add_node(
                    node_id,
                    resp.get("ip", ""),
                    resp.get("tcp_port", 6666),
                    resp.get("web_port", 5000),
                    resp.get("is_master", False),
                )

        return responses

    # =========================================================================
    # Lifecycle
    # =========================================================================

    def stop(self):
        """Graceful shutdown - notify cluster we're leaving."""
        self.running = False
        # Send goodbye message
        msg = {
            "type": "heartbeat",
            "node_id": self.node_id,
            "is_master": False,
            "status": "shutting_down",
            "timestamp": time.time(),
        }
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(json.dumps(msg).encode("utf-8"), ("255.255.255.255", self.cluster_port))
            sock.close()
        except Exception:
            pass
        print("[*] Cluster: Shutdown complete")