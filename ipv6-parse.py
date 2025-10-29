# parser.py
import re
import sys

def parse_mitm6_log(logfile):
    # Regex to find MACs, hostnames, and IPs
    # Adjust these based on the exact mitm6 output you see
    mac_regex = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
    host_regex = re.compile(r"host ([\w\d\-\.$_]+)") # Catches hostnames and FQDNs
    ipv6_regex = re.compile(r"([0-9a-fA-F:]+:+[0-9a-fA-F:]+)") # Basic IPv6 regex
    
    found_macs = set()
    found_hosts = set()
    found_ips = set()

    with open(logfile, 'r') as f:
        for line in f:
            # Look for MACs, hosts, etc.
            # This is a basic example; you'll want to find lines
            # like "Spoofing DNS for HOSTNAME (MAC_ADDRESS)"
            if "Spoofing" in line or "Got request" in line:
                mac = mac_regex.search(line)
                host = host_regex.search(line)
                ip = ipv6_regex.search(line)
                
                if mac:
                    found_macs.add(mac.group(1).lower())
                if host:
                    # Avoid adding your own domain as a "host"
                    if host.group(1) != "your.domain":
                         found_hosts.add(host.group(1))
                if ip:
                    found_ips.add(ip.group(1))

    print("--- Found MACs ---")
    for mac in found_macs:
        print(mac)
    
    print("\n--- Found Hosts ---")
    for host in found_hosts:
        print(host)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <mitm6_attack.log>")
        sys.exit(1)
    parse_mitm6_log(sys.argv[1])
