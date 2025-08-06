import os
import time
import logging
import json
from datetime import datetime

from scapy.all import ARP, Ether, srp, conf
import nmap
from kafka import KafkaProducer

from common.config import get_env

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("asset_discovery")

def arp_scan(network_range):
    """Perform ARP scan on the network, return list of dicts with ip, mac."""
    logger.info(f"Starting ARP scan on {network_range}")
    conf.verb = 0
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_range),
        timeout=3,
        retry=1
    )
    results = []
    for snd, rcv in ans:
        results.append({
            "ip": rcv.psrc,
            "mac": rcv.hwsrc
        })
    logger.info(f"ARP scan found {len(results)} hosts")
    return results

def nmap_host_discovery(network_range):
    """Use nmap to discover live hosts."""
    logger.info(f"Starting nmap host discovery on {network_range}")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_range, arguments='-sn')
    except Exception as e:
        logger.error(f"nmap host discovery failed: {e}")
        return []
    hosts = []
    for host in nm.all_hosts():
        h = {
            "ip": host,
            "hostname": nm[host].hostname() or None
        }
        hosts.append(h)
    logger.info(f"Nmap discovered {len(hosts)} hosts")
    return hosts

def nmap_port_scan(ip):
    """Run nmap port scan for top 1000 ports on host, return list of port dicts."""
    logger.info(f"Scanning ports on {ip}")
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-Pn --top-ports 1000')
    except Exception as e:
        logger.error(f"Nmap port scan on {ip} failed: {e}")
        return []
    ports = []
    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto]:
                portinfo = nm[ip][proto][port]
                ports.append({
                    "port": port,
                    "proto": proto,
                    "state": portinfo.get("state", ""),
                    "service": portinfo.get("name", "")
                })
    return ports

def merge_host_info(arp_hosts, nmap_hosts):
    """Merge ARP and Nmap host lists on IP address."""
    arp_dict = {h["ip"]: h for h in arp_hosts}
    for n in nmap_hosts:
        ip = n["ip"]
        if ip in arp_dict:
            arp_dict[ip]["hostname"] = n.get("hostname")
        else:
            arp_dict[ip] = {"ip": ip, "mac": None, "hostname": n.get("hostname")}
    return list(arp_dict.values())

def main():
    network_range = get_env("NETWORK_RANGE", "192.168.1.0/24")
    scan_interval = int(get_env("SCAN_INTERVAL_SECONDS", 900))
    kafka_bootstrap = get_env("KAFKA_BOOTSTRAP", "kafka:9092")
    kafka_topic = get_env("KAFKA_TOPIC", "asset.discovery")

    logger.info(f"Starting Asset Discovery Service")
    logger.info(f"Config: NETWORK_RANGE={network_range} SCAN_INTERVAL_SECONDS={scan_interval} KAFKA_BOOTSTRAP={kafka_bootstrap} KAFKA_TOPIC={kafka_topic}")

    producer = KafkaProducer(
        bootstrap_servers=kafka_bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5
    )

    while True:
        try:
            arp_hosts = arp_scan(network_range)
            nmap_hosts = nmap_host_discovery(network_range)
            merged_hosts = merge_host_info(arp_hosts, nmap_hosts)

            for host in merged_hosts:
                ports = nmap_port_scan(host["ip"])
                asset_record = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "ip": host["ip"],
                    "mac": host.get("mac"),
                    "hostname": host.get("hostname"),
                    "ports": ports
                }
                logger.info(f"Discovered asset: {asset_record['ip']} ({asset_record.get('hostname')}) - {len(ports)} ports")
                producer.send(kafka_topic, asset_record)
            producer.flush()
            logger.info(f"Asset scan complete. Sleeping for {scan_interval} seconds.")
        except Exception as e:
            logger.exception("Asset discovery cycle failed.")

        time.sleep(scan_interval)

if __name__ == "__main__":
    main()