"""Handles blocking and unblocking of IP addresses."""

import os
import subprocess

def block_ip(ip_address):
    """Blocks an IP address using Windows Firewall or Linux iptables."""
    print(f"[!] ALARM: Malicious traffic detected from {ip_address}. Blocking IP...")
    try:
        if os.name == 'nt':
            # Windows Firewall
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", 
                 f"name=IDPS_Block_{ip_address}", "dir=in", "action=block", f"remoteip={ip_address}"],
                capture_output=True, check=True
            )
        else:
            # Linux iptables
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], 
                           capture_output=True, check=True)
        print(f"[*] Successfully blocked {ip_address}")
    except Exception as e:
        print(f"[-] Failed to block {ip_address}: {e}")

def unblock_ip(ip_address):
    """Unblocks an IP address using Windows Firewall or Linux iptables."""
    print(f"[*] Block expired for {ip_address}. Unblocking...")
    try:
        if os.name == 'nt':
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", 
                 f"name=IDPS_Block_{ip_address}"],
                capture_output=True, check=True
            )
        else:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], 
                           capture_output=True, check=True)
        print(f"[*] Successfully unblocked {ip_address}")
    except Exception as e:
        print(f"[-] Failed to unblock {ip_address}: {e}")
