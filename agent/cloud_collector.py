"""
Cloud / Container Collector for GIAM-SAT Agent v1.7.0
Monitors Docker containers and Kubernetes clusters for security events.
- Docker: container lifecycle events, image vulnerabilities
- Kubernetes: pod security context, network policies, RBAC, secrets

Requires: docker (Python SDK) for Docker, kubernetes (Python SDK) for K8s.
Gracefully skips if SDKs not available.
"""
import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Docker SDK
try:
    import docker
    HAS_DOCKER_SDK = True
except ImportError:
    HAS_DOCKER_SDK = False

# Kubernetes SDK
try:
    from kubernetes import client as k8s_client, config as k8s_config
    HAS_K8S_SDK = True
except ImportError:
    HAS_K8S_SDK = False


def _run_hidden(cmd, **kwargs):
    kwargs.setdefault("timeout", 15)
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", CREATE_NO_WINDOW)
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def _check_docker_cli():
    """Check if docker CLI is available."""
    try:
        r = _run_hidden(["docker", "version", "--format", "json"], timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return True
    except Exception:
        pass
    return False


def _check_kubectl():
    """Check if kubectl is available."""
    try:
        r = _run_hidden(["kubectl", "version", "--client", "--output=json"], timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return True
    except Exception:
        pass
    return False


class DockerCollector:
    """Collects Docker container security events."""

    def __init__(self, callback=None, check_interval=300):
        self.callback = callback
        self.check_interval = check_interval
        self.running = False
        self._thread = None
        self._docker_client = None
        self._use_sdk = False
        self._use_cli = False

    def _init_client(self):
        """Initialize Docker client (SDK preferred, CLI fallback)."""
        if HAS_DOCKER_SDK:
            try:
                self._docker_client = docker.from_env()
                self._use_sdk = True
                print("[*] Cloud Collector: Docker SDK initialized")
                return True
            except Exception:
                pass

        if _check_docker_cli():
            self._use_cli = True
            print("[*] Cloud Collector: Using docker CLI")
            return True

        print("[*] Cloud Collector: Docker not available")
        return False

    def start(self):
        """Start Docker monitoring."""
        if not self._init_client():
            return
        self.running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print("[*] Cloud Collector: Docker monitoring started")

    def _monitor_loop(self):
        """Periodic monitoring loop."""
        while self.running:
            try:
                self.scan_containers()
                self.scan_images()
            except Exception as e:
                print(f"[-] Cloud Collector Docker error: {e}")
            time.sleep(self.check_interval)

    def scan_containers(self):
        """Scan running Docker containers for security issues."""
        containers = []

        if self._use_sdk and self._docker_client:
            try:
                containers = self._docker_client.containers.list(all=True)
                self._process_containers_sdk(containers)
            except Exception as e:
                print(f"[-] Docker SDK container error: {e}")
        elif self._use_cli:
            self._process_containers_cli()

    def _process_containers_sdk(self, containers):
        """Process containers via Docker SDK."""
        for container in containers:
            try:
                attrs = container.attrs
                config = attrs.get("Config", {})
                host_config = attrs.get("HostConfig", {})

                issues = []

                # Check privileged mode
                if host_config.get("Privileged", False):
                    issues.append("Container running in PRIVILEGED mode")

                # Check for host network mode
                if host_config.get("NetworkMode", "") == "host":
                    issues.append("Container using HOST network mode")

                # Check for host PID namespace
                if host_config.get("PidMode", "") == "host":
                    issues.append("Container using HOST PID namespace")

                # Check for sensitive mounts
                mounts = host_config.get("Mounts", []) + host_config.get("Binds", [])
                sensitive_paths = ["/var/run/docker.sock", "/proc", "/sys", "/", "/etc"]
                for mount in mounts:
                    mount_src = mount.get("Source", "") if isinstance(mount, dict) else mount.split(":")[0] if ":" in str(mount) else str(mount)
                    for sensitive in sensitive_paths:
                        if sensitive in mount_src:
                            issues.append(f"Sensitive mount: {mount_src}")
                            break

                # Check for no security options
                security_opt = host_config.get("SecurityOpt", [])
                if not security_opt:
                    issues.append("No security options configured (no SELinux/AppArmor)")

                # Check capabilities
                cap_add = host_config.get("CapAdd", [])
                dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
                                   "DAC_OVERRIDE", "DAC_READ_SEARCH", "NET_RAW"]
                for cap in cap_add:
                    if cap in dangerous_caps:
                        issues.append(f"Dangerous capability added: {cap}")

                # Check readonly rootfs
                if not host_config.get("ReadonlyRootfs", False):
                    issues.append("Root filesystem is WRITABLE")

                if issues:
                    for issue in issues:
                        self._send_event("docker_security", container.name, issue, "HIGH")
                else:
                    self._send_event("docker_security", container.name,
                                     "Container configuration passes basic checks", "LOW")

            except Exception as e:
                self._send_event("docker_security", "unknown",
                                 f"Error checking container: {e}", "LOW")

    def _process_containers_cli(self):
        """Process containers via Docker CLI (fallback)."""
        try:
            # List containers
            r = _run_hidden(["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"], timeout=10)
            if r.returncode != 0:
                return

            for line in r.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                name = parts[0]
                image = parts[1]

                # Check if container runs as root
                r2 = _run_hidden(["docker", "inspect", name,
                                  "--format", "{{.Config.User}}"], timeout=10)
                user = r2.stdout.strip() if r2.returncode == 0 else ""
                if not user or user == "root" or user == "0":
                    self._send_event("docker_security", name,
                                     f"Container running as root", "HIGH")

                # Check privileged
                r3 = _run_hidden(["docker", "inspect", name,
                                  "--format", "{{.HostConfig.Privileged}}"], timeout=10)
                if r3.returncode == 0 and r3.stdout.strip() == "true":
                    self._send_event("docker_security", name,
                                     "Container running in PRIVILEGED mode", "CRITICAL")

        except Exception as e:
            self._send_event("docker_security", "cli", f"CLI error: {e}", "LOW")

    def scan_images(self):
        """Scan Docker images for known vulnerabilities (basic checks)."""
        if self._use_sdk and self._docker_client:
            try:
                images = self._docker_client.images.list()
                for img in images:
                    tags = img.tags
                    if not tags:
                        tags = ["<none>:<none>"]
                    for tag in tags:
                        if "latest" in tag:
                            self._send_event("docker_image", tag,
                                             "Image tagged as 'latest' - consider pinning version", "LOW")
            except Exception:
                pass
        elif self._use_cli:
            try:
                r = _run_hidden(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"], timeout=10)
                for line in r.stdout.strip().split("\n"):
                    if "latest" in line:
                        self._send_event("docker_image", line.strip(),
                                         "Image tagged as 'latest'", "LOW")
            except Exception:
                pass

    def _send_event(self, event_type, resource_name, description, severity):
        """Send a Docker/K8s event via callback."""
        event = {
            "type": "cloud_event",
            "subtype": event_type,
            "resource": resource_name,
            "description": description,
            "severity": severity,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        if self.callback:
            self.callback(event)

    def stop(self):
        self.running = False


class K8sCollector:
    """Collects Kubernetes cluster security events."""

    def __init__(self, callback=None, check_interval=300):
        self.callback = callback
        self.check_interval = check_interval
        self.running = False
        self._thread = None
        self._use_k8s_sdk = False
        self._use_kubectl = False

    def _init(self):
        """Initialize Kubernetes client."""
        if HAS_K8S_SDK:
            try:
                k8s_config.load_kube_config()
                self._use_k8s_sdk = True
                print("[*] Cloud Collector: K8s SDK initialized")
                return True
            except Exception:
                try:
                    k8s_config.load_incluster_config()
                    self._use_k8s_sdk = True
                    print("[*] Cloud Collector: K8s SDK (in-cluster) initialized")
                    return True
                except Exception:
                    pass

        if _check_kubectl():
            self._use_kubectl = True
            print("[*] Cloud Collector: Using kubectl CLI")
            return True

        print("[*] Cloud Collector: K8s not available")
        return False

    def start(self):
        """Start K8s monitoring."""
        if not self._init():
            return
        self.running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print("[*] Cloud Collector: K8s monitoring started")

    def _monitor_loop(self):
        """Periodic monitoring loop."""
        while self.running:
            try:
                self._check_pod_security()
                self._check_network_policies()
                self._check_rbac()
                self._check_secrets()
                self._check_pod_security_standards()
            except Exception as e:
                print(f"[-] Cloud Collector K8s error: {e}")
            time.sleep(self.check_interval)

    def _check_pod_security(self):
        """Check pod security contexts for best practices violations."""
        if self._use_k8s_sdk:
            try:
                v1 = k8s_client.CoreV1Api()
                pods = v1.list_pod_for_all_namespaces()
                for pod in pods.items:
                    issues = []
                    spec = pod.spec
                    security_context = spec.security_context

                    for container in spec.containers:
                        ctx = container.security_context
                        if ctx:
                            if ctx.privileged:
                                issues.append(f"Container '{container.name}': PRIVILEGED")
                            if ctx.run_as_user == 0:
                                issues.append(f"Container '{container.name}': Runs as ROOT")
                            if ctx.allow_privilege_escalation:
                                issues.append(f"Container '{container.name}': Privilege escalation ALLOWED")
                            caps_add = ctx.capabilities.add if ctx.capabilities else []
                            dangerous = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
                            for cap in caps_add:
                                if cap in dangerous:
                                    issues.append(f"Container '{container.name}': Dangerous cap {cap}")
                            if ctx.read_only_root_filesystem is False:
                                issues.append(f"Container '{container.name}': Writable rootfs")
                        else:
                            issues.append(f"Container '{container.name}': No security context")

                    if issues:
                        for issue in issues:
                            self._send_k8s_event("pod_security", f"{pod.metadata.namespace}/{pod.metadata.name}", issue, "HIGH")
            except Exception:
                pass
        elif self._use_kubectl:
            try:
                r = _run_hidden(["kubectl", "get", "pods", "--all-namespaces",
                                 "-o", "json"], timeout=30)
                if r.returncode == 0 and r.stdout:
                    data = json.loads(r.stdout)
                    for item in data.get("items", []):
                        meta = item.get("metadata", {})
                        namespace = meta.get("namespace", "")
                        name = meta.get("name", "")
                        spec = item.get("spec", {})
                        containers = spec.get("containers", [])
                        for c in containers:
                            ctx = c.get("securityContext", {})
                            if ctx:
                                if ctx.get("privileged"):
                                    self._send_k8s_event("pod_security",
                                        f"{namespace}/{name}",
                                        f"Container '{c['name']}' is PRIVILEGED", "CRITICAL")
            except Exception:
                pass

    def _check_network_policies(self):
        """Check for missing network policies."""
        if self._use_k8s_sdk:
            try:
                net_v1 = k8s_client.NetworkingV1Api()
                policies = net_v1.list_network_policy_for_all_namespaces()
                namespaces_no_policy = set()

                v1 = k8s_client.CoreV1Api()
                all_ns = [ns.metadata.name for ns in v1.list_namespace().items]
                ns_with_policy = {p.metadata.namespace for p in policies.items}
                namespaces_no_policy = set(all_ns) - ns_with_policy

                for ns in namespaces_no_policy:
                    self._send_k8s_event("network_policy", ns,
                                         "No NetworkPolicy defined - all traffic allowed", "HIGH")
            except Exception:
                pass
        elif self._use_kubectl:
            try:
                r = _run_hidden(["kubectl", "get", "networkpolicies", "--all-namespaces",
                                 "-o", "json"], timeout=15)
                if r.returncode == 0:
                    data = json.loads(r.stdout)
                    ns_with_policy = set()
                    for item in data.get("items", []):
                        ns_with_policy.add(item.get("metadata", {}).get("namespace", ""))

                    r2 = _run_hidden(["kubectl", "get", "namespaces", "-o", "json"], timeout=10)
                    if r2.returncode == 0:
                        ns_data = json.loads(r2.stdout)
                        for item in ns_data.get("items", []):
                            ns_name = item.get("metadata", {}).get("name", "")
                            if ns_name not in ns_with_policy and ns_name != "kube-system":
                                self._send_k8s_event("network_policy", ns_name,
                                                     "No NetworkPolicy defined", "HIGH")
            except Exception:
                pass

    def _check_rbac(self):
        """Check RBAC for overly permissive ClusterRoleBindings."""
        if self._use_kubectl:
            try:
                r = _run_hidden(["kubectl", "get", "clusterrolebindings", "-o", "json"], timeout=15)
                if r.returncode == 0:
                    data = json.loads(r.stdout)
                    for item in data.get("items", []):
                        role_ref = item.get("roleRef", {})
                        if role_ref.get("name") == "cluster-admin":
                            subjects = item.get("subjects", [])
                            for subj in subjects:
                                if subj.get("kind") == "ServiceAccount":
                                    self._send_k8s_event("rbac",
                                        f"{item.get('metadata',{}).get('name','')}",
                                        f"ServiceAccount '{subj.get('name','')}' has cluster-admin",
                                        "CRITICAL")
            except Exception:
                pass

    def _check_secrets(self):
        """Check for secrets containing 'password' in name (quick scan)."""
        if self._use_kubectl:
            try:
                r = _run_hidden(["kubectl", "get", "secrets", "--all-namespaces",
                                 "-o", "json"], timeout=15)
                if r.returncode == 0:
                    data = json.loads(r.stdout)
                    for item in data.get("items", []):
                        name = item.get("metadata", {}).get("name", "").lower()
                        ns = item.get("metadata", {}).get("namespace", "")
                        if "password" in name or "credential" in name or "token" in name:
                            data_keys = list(item.get("data", {}).keys())
                            self._send_k8s_event("secret",
                                f"{ns}/{name}",
                                f"Secret with sensitive name found. Keys: {', '.join(data_keys[:5])}",
                                "MEDIUM")
            except Exception:
                pass

    def _check_pod_security_standards(self):
        """Check namespace Pod Security Standards labels."""
        if self._use_kubectl:
            try:
                r = _run_hidden(["kubectl", "get", "namespaces", "-o", "json"], timeout=10)
                if r.returncode == 0:
                    data = json.loads(r.stdout)
                    for item in data.get("items", []):
                        meta = item.get("metadata", {})
                        labels = meta.get("labels", {})
                        ns_name = meta.get("name", "")
                        # Skip kube-system
                        if ns_name in ("kube-system", "kube-public", "kube-node-lease"):
                            continue
                        if "pod-security.kubernetes.io/enforce" not in labels:
                            self._send_k8s_event("pod_security_standard", ns_name,
                                                 "No Pod Security Standard enforced", "MEDIUM")
            except Exception:
                pass

    def _send_k8s_event(self, event_type, resource_name, description, severity):
        event = {
            "type": "cloud_event",
            "subtype": f"k8s_{event_type}",
            "resource": resource_name,
            "description": description,
            "severity": severity,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        if self.callback:
            self.callback(event)

    def stop(self):
        self.running = False


class CloudCollector:
    """Unified Cloud/Container Security Collector.

    Combines Docker + Kubernetes monitoring into a single module.
    """

    def __init__(self, callback=None, check_interval=300):
        self.callback = callback
        self.docker = DockerCollector(callback=callback, check_interval=check_interval)
        self.k8s = K8sCollector(callback=callback, check_interval=check_interval)

    def start(self):
        """Start all cloud collectors."""
        self.docker.start()
        self.k8s.start()

    def stop(self):
        """Stop all cloud collectors."""
        self.docker.stop()
        self.k8s.stop()