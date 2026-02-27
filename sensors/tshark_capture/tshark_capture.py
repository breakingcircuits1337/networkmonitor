#!/usr/bin/env python3
import os
import subprocess
import time
from datetime import datetime
from kafka import KafkaProducer
import json

INTERFACE             = os.getenv('INTERFACE', 'eth0')
CAPTURE_DIR           = os.getenv('CAPTURE_DIR', '/captures')
KAFKA_BOOTSTRAP       = os.getenv('KAFKA_BOOTSTRAP', 'kafka:9092')
KAFKA_TOPIC           = os.getenv('KAFKA_TOPIC', 'voip.packets')
RAW_FLOWS_TOPIC       = os.getenv('RAW_FLOWS_TOPIC', 'raw.flows')
ROTATION_SECONDS      = int(os.getenv('ROTATION_SECONDS', '30'))
MAX_FLOWS_PER_ROTATION = int(os.getenv('MAX_FLOWS_PER_ROTATION', '200'))

os.makedirs(CAPTURE_DIR, exist_ok=True)

try:
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )
    kafka_available = True
except Exception as e:
    print(f"Kafka not available: {e}")
    kafka_available = False

PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}


def analyze_raw_flows(pcap_file):
    """Extract per-flow stats from pcap: src/dst/proto/ports/bytes/packets."""
    try:
        result = subprocess.run([
            'tshark', '-r', pcap_file,
            '-T', 'fields',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'ip.proto',
            '-e', 'frame.len',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-Y', 'ip',
            '-E', 'separator=|',
        ], capture_output=True, text=True, timeout=30)

        flows = {}
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split('|')
            if len(parts) < 9:
                continue
            ts_s, src_ip, dst_ip, proto_s, len_s = parts[0], parts[1], parts[2], parts[3], parts[4]
            tcp_sp, tcp_dp, udp_sp, udp_dp = parts[5], parts[6], parts[7], parts[8]

            if not src_ip or not dst_ip:
                continue

            try:
                src_port  = int(tcp_sp or udp_sp or 0)
                dst_port  = int(tcp_dp or udp_dp or 0)
                proto_num = int(proto_s) if proto_s else 0
                length    = int(len_s) if len_s else 0
                ts_epoch  = float(ts_s) if ts_s else 0.0
            except (ValueError, TypeError):
                continue

            key = (src_ip, dst_ip, src_port, dst_port, proto_num)
            if key not in flows:
                flows[key] = {
                    'src_ip':     src_ip,
                    'dst_ip':     dst_ip,
                    'src_port':   src_port,
                    'dst_port':   dst_port,
                    'protocol':   proto_num,
                    'proto_name': PROTO_NAME.get(proto_num, str(proto_num)),
                    'bytes':      0,
                    'packets':    0,
                    'first_seen': ts_epoch,
                    'last_seen':  ts_epoch,
                }
            flows[key]['bytes']   += length
            flows[key]['packets'] += 1
            if ts_epoch > flows[key]['last_seen']:
                flows[key]['last_seen'] = ts_epoch

        # Sort by bytes descending — most interesting flows first
        return sorted(flows.values(), key=lambda f: f['bytes'], reverse=True)

    except Exception as e:
        print(f"Error analyzing raw flows: {e}")
        return []


def get_voip_summary(pcap_file):
    try:
        result = subprocess.run(
            ['tshark', '-r', pcap_file, '-q', '-z', 'voip,calls'],
            capture_output=True, text=True, timeout=30)
        return result.stdout
    except Exception as e:
        return f"Error: {e}"


def analyze_sip_calls(pcap_file):
    try:
        result = subprocess.run([
            'tshark', '-r', pcap_file,
            '-Y', 'sip',
            '-T', 'fields',
            '-e', 'sip.method',
            '-e', 'sip.call-id',
            '-e', 'sip.from',
            '-e', 'sip.to',
            '-e', 'frame.time',
        ], capture_output=True, text=True, timeout=30)
        calls = []
        for line in result.stdout.strip().split('\n'):
            if line:
                parts = line.split('\t')
                if len(parts) >= 5:
                    calls.append({'method': parts[0], 'call_id': parts[1],
                                  'from': parts[2], 'to': parts[3], 'time': parts[4]})
        return calls
    except Exception:
        return []


def capture_loop():
    print(f"tshark capture — interface={INTERFACE} rotation={ROTATION_SECONDS}s")
    rotation_count = 0

    while True:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = f"{CAPTURE_DIR}/capture_{timestamp}_{rotation_count:04d}.pcap"

        print(f"Starting capture: {pcap_file}")
        try:
            proc = subprocess.Popen([
                'tshark', '-i', INTERFACE,
                '-w', pcap_file, '-F', 'pcap',
                '-a', f'duration:{ROTATION_SECONDS}',
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.wait(timeout=ROTATION_SECONDS + 10)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait()
        except Exception as e:
            print(f"Capture error: {e}")

        print(f"Capture complete: {pcap_file}")

        if not kafka_available:
            rotation_count += 1
            time.sleep(1)
            continue

        now_iso = datetime.utcnow().isoformat() + "Z"

        # ── Raw flows → raw.flows ────────────────────────────────────────────
        try:
            raw_flows = analyze_raw_flows(pcap_file)
            sent = 0
            for flow in raw_flows[:MAX_FLOWS_PER_ROTATION]:
                flow['timestamp'] = now_iso
                flow['topic']     = RAW_FLOWS_TOPIC
                producer.send(RAW_FLOWS_TOPIC, value=flow)
                sent += 1
            if sent:
                print(f"Sent {sent} raw flows → {RAW_FLOWS_TOPIC}")
        except Exception as e:
            print(f"Error sending raw flows: {e}")

        # ── VoIP / SIP → voip.packets ────────────────────────────────────────
        try:
            calls = analyze_sip_calls(pcap_file)
            if calls:
                producer.send(KAFKA_TOPIC, value={
                    'timestamp':        now_iso,
                    'pcap_file':        pcap_file,
                    'summary':          get_voip_summary(pcap_file),
                    'sip_calls':        calls,
                    'capture_duration': ROTATION_SECONDS,
                })
                print(f"Sent {len(calls)} SIP calls → {KAFKA_TOPIC}")
        except Exception as e:
            print(f"Error sending VoIP: {e}")

        # Keep last 10 pcaps only
        try:
            pcaps = sorted(f for f in os.listdir(CAPTURE_DIR) if f.endswith('.pcap'))
            for old in pcaps[:-10]:
                os.remove(os.path.join(CAPTURE_DIR, old))
        except Exception:
            pass

        rotation_count += 1
        time.sleep(1)


if __name__ == '__main__':
    capture_loop()
