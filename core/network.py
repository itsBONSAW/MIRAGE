from __future__ import annotations

import subprocess
import threading
import xml.etree.ElementTree as ET


class NetworkScanner:
    def __init__(
        self,
        interface: str,
        on_log_callback,
        on_host_callback,
    ):
        self.interface = interface
        self.on_log = on_log_callback
        self.on_host = on_host_callback

        self.stop_event = threading.Event()

        self.thread: threading.Thread | None = None
        self.process: subprocess.Popen[str] | None = None

        self.process_lock = threading.Lock()
        self.lifecycle_lock = threading.Lock()

        self.running = False

    def is_alive(self) -> bool:
        thread = self.thread
        return bool(
            thread
            and thread.is_alive()
        )

    def start(
        self,
        subnet: str,
    ) -> None:
        with self.lifecycle_lock:
            if self.running:
                raise RuntimeError(
                    "Network scanner is already running"
                )

            self.stop_event.clear()

            self.thread = threading.Thread(
                target=self._scan_loop,
                args=(subnet,),
                name="mirage-network-scanner",
                daemon=True,
            )

            self.running = True
            self.thread.start()

    def stop(self) -> None:
        with self.lifecycle_lock:
            if not self.running:
                return

            self.stop_event.set()

            with self.process_lock:
                process = self.process

            if process is not None:
                try:
                    process.terminate()
                except Exception:
                    pass

                try:
                    process.wait(
                        timeout=2
                    )
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                    finally:
                        process.wait(
                            timeout=2
                        )

            thread = self.thread

            if thread is not None:
                thread.join(
                    timeout=3
                )

                if thread.is_alive():
                    raise RuntimeError(
                        "Network scanner thread did not stop gracefully"
                    )

            self.thread = None
            self.running = False

            self.on_log(
                "[!] Network scan stopped."
            )

    def _scan_loop(
        self,
        subnet: str,
    ) -> None:
        self.on_log(
            f"[*] Running nmap scan on {subnet}..."
        )

        command = [
            "nmap",
            "-sn",
            "-oX",
            "-",
            subnet,
        ]

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )

            with self.process_lock:
                self.process = process

            stdout, _ = process.communicate()

            if self.stop_event.is_set():
                return

            if process.returncode not in (
                0,
                None,
            ):
                raise RuntimeError(
                    f"Nmap exited with code {process.returncode}"
                )

            hosts = self._parse_xml(
                stdout
            )

            if not self.stop_event.is_set():
                self.on_host(hosts)
                self.on_log(
                    f"[*] Scan complete. Found {len(hosts)} active hosts."
                )

        except FileNotFoundError as exc:
            self.on_log(
                f"[-] Nmap is not installed: {exc}"
            )

        except ET.ParseError as exc:
            self.on_log(
                f"[-] Failed to parse Nmap XML: {exc}"
            )

        except Exception as exc:
            if not self.stop_event.is_set():
                self.on_log(
                    f"[-] Scan error: {exc}"
                )

        finally:
            with self.process_lock:
                self.process = None

            self.running = False

    def _parse_xml(
        self,
        xml_data: str,
    ) -> list[dict[str, str]]:
        root = ET.fromstring(
            xml_data
        )

        hosts: list[dict[str, str]] = []

        for host in root.findall(
            ".//host"
        ):
            status = host.find(
                "status"
            )

            if (
                status is not None
                and status.get("state") != "up"
            ):
                continue

            ip_value = "Unknown"
            mac_value = "Unknown"
            vendor_value = "Unknown"
            hostname_value = "Unknown"

            for address in host.findall(
                "address"
            ):
                address_type = address.get(
                    "addrtype"
                )

                if address_type == "ipv4":
                    ip_value = (
                        address.get(
                            "addr"
                        )
                        or "Unknown"
                    )

                elif address_type == "mac":
                    mac_value = (
                        address.get(
                            "addr"
                        )
                        or "Unknown"
                    )

                    vendor_value = (
                        address.get(
                            "vendor"
                        )
                        or "Unknown"
                    )

            hostname = host.find(
                "./hostnames/hostname"
            )

            if hostname is not None:
                hostname_value = (
                    hostname.get(
                        "name"
                    )
                    or "Unknown"
                )

            if ip_value != "Unknown":
                hosts.append(
                    {
                        "ip": ip_value,
                        "mac": mac_value,
                        "vendor": vendor_value,
                        "hostname": hostname_value,
                    }
                )

        return hosts