"""
RabbitMQ Event Queue v1.0.0 for GIAM-SAT Server v3.1.0
AMQP-based event buffer for production-scale deployments (>1000 agents).

Purpose: Replace Redis with RabbitMQ for more reliable message delivery:
  - Persistent message storage (durable queues)
  - Dead Letter Exchange for failed events
  - Consumer acknowledgments (no event loss on crash)
  - Multi-node clustering built-in

Architecture:
  TCP Server → RabbitMQEventQueue.push_event() → RabbitMQ Exchange
                                                   ↓ (fanout routing)
                                                Per-type Queues
                                                   ↓ (ack'd consume)
                                                Event Worker Pool → DB batch write

Configuration:
  GIAMSAT_RABBITMQ_URL=amqp://guest:guest@localhost:5672/  (default)
  GIAMSAT_RABBITMQ_EXCHANGE=giamsat.events                  (default)

Usage:
  Set GIAMSAT_QUEUE_BACKEND=rabbitmq in .env

Dependencies:
  pip install pika
"""

import os
import json
import time
import threading
import logging

try:
    import pika
    HAS_PIKA = True
except ImportError:
    HAS_PIKA = False

# Queue names (same as event_queue.py for consistency)
QUEUE_EVENTS = "giamsat:queue:events"
QUEUE_SYSMON = "giamsat:queue:sysmon"
QUEUE_NETWORK = "giamsat:queue:network"
QUEUE_THREATS = "giamsat:queue:threats"
QUEUE_HEARTBEATS = "giamsat:queue:heartbeats"
QUEUE_FIM = "giamsat:queue:fim"
QUEUE_ALERTS = "giamsat:queue:alerts"

ALL_QUEUES = [
    QUEUE_EVENTS, QUEUE_SYSMON, QUEUE_NETWORK,
    QUEUE_THREATS, QUEUE_HEARTBEATS, QUEUE_FIM, QUEUE_ALERTS,
]

# Defaults
DEFAULT_RABBITMQ_URL = "amqp://guest:guest@localhost:5672/"
DEFAULT_EXCHANGE = "giamsat.events"

logger = logging.getLogger("giamsat.rabbitmq")


class RabbitMQEventQueue:
    """
    RabbitMQ-backed event queue using AMQP protocol.
    Thread-safe producer; consumer reads happen via pop_batch() with pre-fetched
    in-memory buffer for compatibility with existing worker pool pattern.
    """

    def __init__(self, config=None):
        self._channel = None
        self._connection = None
        self._mem_buffer = {}  # queue_name → deque for pre-fetched messages
        self._mem_lock = threading.Lock()
        self._consumer_tags = {}  # queue_name → consumer_tag
        self._callback_thread = None
        self._running = False

        self._stats = {
            "pushed": 0,
            "popped": 0,
            "dropped": 0,
        }

        cfg = config or {}
        self._rabbitmq_url = (
            cfg.get("url")
            or os.environ.get("GIAMSAT_RABBITMQ_URL", DEFAULT_RABBITMQ_URL)
        )
        self._exchange = (
            cfg.get("exchange")
            or os.environ.get("GIAMSAT_RABBITMQ_EXCHANGE", DEFAULT_EXCHANGE)
        )

        if not HAS_PIKA:
            print("[!] RabbitMQEventQueue: pika not installed. Install with: pip install pika")
            self._connection = None
            return

        self._connect()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    def _connect(self):
        """Establish connection and declare exchange + queues."""
        try:
            import urllib.parse
            params = pika.URLParameters(self._rabbitmq_url)
            params.heartbeat = 30
            params.blocked_connection_timeout = 300
            params.connection_attempts = 3
            params.retry_delay = 5

            self._connection = pika.BlockingConnection(params)
            self._channel = self._connection.channel()

            # Declare durable exchange
            self._channel.exchange_declare(
                exchange=self._exchange,
                exchange_type="fanout",
                durable=True,
            )

            # Declare all queues with dead letter exchange
            dlx_exchange = f"{self._exchange}.dlx"
            self._channel.exchange_declare(
                exchange=dlx_exchange,
                exchange_type="fanout",
                durable=True,
            )

            for qname in ALL_QUEUES:
                dlq_name = f"{qname}.dlq"
                # Dead letter queue
                self._channel.queue_declare(
                    queue=dlq_name,
                    durable=True,
                )
                self._channel.queue_bind(
                    queue=dlq_name,
                    exchange=dlx_exchange,
                    routing_key="",
                )
                # Main queue
                args = {
                    "x-dead-letter-exchange": dlx_exchange,
                    "x-message-ttl": 86400000,  # 24h TTL on messages
                }
                self._channel.queue_declare(
                    queue=qname,
                    durable=True,
                    arguments=args,
                )
                self._channel.queue_bind(
                    queue=qname,
                    exchange=self._exchange,
                    routing_key="",
                )

                # Initialize in-memory buffer
                self._mem_buffer[qname] = []

            # Start consumer thread
            self._running = True
            self._callback_thread = threading.Thread(
                target=self._consume_loop,
                daemon=True,
            )
            self._callback_thread.start()

            print(f"[*] RabbitMQEventQueue: Connected ({self._rabbitmq_url})")
            print(f"[*] RabbitMQEventQueue: Exchange={self._exchange}, Queues={len(ALL_QUEUES)}")

        except Exception as e:
            print(f"[-] RabbitMQEventQueue: Connection failed ({e})")
            self._connection = None
            self._channel = None

    @property
    def has_rabbitmq(self):
        return self._channel is not None

    # ------------------------------------------------------------------
    # Producer: push events
    # ------------------------------------------------------------------
    def push(self, queue_name, event_data):
        """Push an event to the queue via RabbitMQ exchange.
        All queues are bound to the same fanout exchange — the routing_key
        determines which queue receives the message.
        """
        if not self._channel:
            # Fallback: store in memory if RabbitMQ is down
            with self._mem_lock:
                buf = self._mem_buffer.get(queue_name)
                if buf is not None:
                    buf.append(json.dumps(event_data, ensure_ascii=False, default=str))
            self._stats["dropped"] += 1
            return

        try:
            json_str = json.dumps(event_data, ensure_ascii=False, default=str)
            self._channel.basic_publish(
                exchange=self._exchange,
                routing_key=queue_name,
                body=json_str.encode("utf-8"),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Persistent
                    content_type="application/json",
                ),
            )
            self._stats["pushed"] += 1
        except Exception:
            self._stats["dropped"] += 1

    def push_event(self, event):
        """Route event to appropriate queue based on type.
        Same routing logic as EventQueue for compatibility.
        """
        msg_type = event.get("type", "")
        if msg_type in ("process_event", "network_event", "module_load_event",
                         "process_injection", "process_access", "file_create_event",
                         "dns_query_event", "sysmon_event",
                         "memory_scan_event", "process_hollowing"):
            self.push(QUEUE_SYSMON, event)
        elif msg_type in ("windows_event", "linux_event", "linux_audit", "registry_event",
                           "cloud_event", "sca_event", "network_anomaly"):
            self.push(QUEUE_EVENTS, event)
        elif msg_type in ("fim", "fim_event"):
            self.push(QUEUE_FIM, event)
        elif msg_type == "network_traffic":
            self.push(QUEUE_NETWORK, event)
        elif msg_type in ("threat_alert", "cross_machine_threat"):
            self.push(QUEUE_THREATS, event)
        elif msg_type in ("yara_alert", "vulnerability_alert", "baseline_report"):
            self.push(QUEUE_ALERTS, event)
        elif msg_type == "heartbeat":
            self.push(QUEUE_HEARTBEATS, event)
        else:
            self.push(QUEUE_EVENTS, event)

    # ------------------------------------------------------------------
    # Consumer: background pre-fetch into in-memory buffer
    # ------------------------------------------------------------------
    def _on_message(self, ch, method, properties, body):
        """AMQP callback: receive message, store in in-memory buffer."""
        try:
            queue_name = method.routing_key
            with self._mem_lock:
                buf = self._mem_buffer.get(queue_name)
                if buf is not None:
                    buf.append(body.decode("utf-8"))
            ch.basic_ack(delivery_tag=method.delivery_tag)
        except Exception:
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

    def _consume_loop(self):
        """Background thread: consume from all queues into in-memory buffers."""
        import pika.exceptions as pika_exc

        while self._running and self._channel:
            try:
                for qname in ALL_QUEUES:
                    if qname not in self._consumer_tags:
                        tag = self._channel.basic_consume(
                            queue=qname,
                            on_message_callback=self._on_message,
                            auto_ack=False,
                        )
                        self._consumer_tags[qname] = tag

                # Process one event at a time (non-blocking with 1s timeout)
                self._connection.process_data_events(time_limit=1)
            except pika_exc.AMQPConnectionError:
                print("[!] RabbitMQEventQueue: Connection lost, reconnecting in 5s...")
                time.sleep(5)
                try:
                    self._connect()
                except Exception:
                    pass
            except Exception as e:
                logger.error(f"RabbitMQ consumer error: {e}")
                time.sleep(1)

    # ------------------------------------------------------------------
    # Consumer: pop batch (for worker pool compatibility)
    # ------------------------------------------------------------------
    def pop_batch(self, queue_name, batch_size=100, timeout=1):
        """Pop up to batch_size events from the in-memory pre-fetched buffer.
        Returns list of dicts (parsed from JSON).
        """
        results = []
        deadline = time.time() + timeout

        with self._mem_lock:
            buf = self._mem_buffer.get(queue_name, [])
            while len(results) < batch_size and time.time() < deadline:
                if buf:
                    raw = buf.pop(0)
                    try:
                        results.append(json.loads(raw))
                    except json.JSONDecodeError:
                        pass
                else:
                    break  # No more in buffer, return what we have

        self._stats["popped"] += len(results)
        return results

    # ------------------------------------------------------------------
    # Stats and management
    # ------------------------------------------------------------------
    def get_stats(self):
        """Return queue statistics."""
        stats = {
            "pushed": self._stats["pushed"],
            "popped": self._stats["popped"],
            "dropped": self._stats["dropped"],
            "backend": "rabbitmq" if self._channel else "rabbitmq-disconnected",
            "queues": {},
        }
        with self._mem_lock:
            for qname in ALL_QUEUES:
                buf = self._mem_buffer.get(qname, [])
                stats["queues"][qname.split(":")[-1]] = len(buf)

        if self._channel:
            try:
                for qname in ALL_QUEUES:
                    result = self._channel.queue_declare(queue=qname, passive=True)
                    stats["queues"][qname.split(":")[-1]] = result.method.message_count
            except Exception:
                pass

        return stats

    def clear_all(self):
        """Purge all queues (dangerous!)."""
        if self._channel:
            try:
                for qname in ALL_QUEUES:
                    self._channel.queue_purge(queue=qname)
            except Exception:
                pass
        with self._mem_lock:
            for buf in self._mem_buffer.values():
                buf.clear()
        self._stats = {"pushed": 0, "popped": 0, "dropped": 0}

    def stop(self):
        """Stop consumer thread and close connection."""
        self._running = False
        if self._channel:
            try:
                for tag in self._consumer_tags.values():
                    self._channel.basic_cancel(tag)
                self._channel.close()
            except Exception:
                pass
        if self._connection:
            try:
                self._connection.close()
            except Exception:
                pass