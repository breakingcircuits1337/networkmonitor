#!/usr/bin/env python3
import os
import json
import re
import threading
from datetime import datetime
from kafka import KafkaProducer
import pyshark

KAFKA_BOOTSTRAP = os.getenv('KAFKA_BOOTSTRAP', 'kafka:9092')
KAFKA_TOPIC = os.getenv('KAFKA_TOPIC', 'voip.events')
INTERFACE = os.getenv('INTERFACE', 'eth0')

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP,
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

active_calls = {}
call_lock = threading.Lock()

def parse_sip_packet(pkt):
    if not hasattr(pkt, 'sip'):
        return None
    
    sip_layer = pkt.sip
    src_ip = pkt.ip.src if hasattr(pkt, 'ip') else 'unknown'
    dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else 'unknown'
    
    event = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'method': getattr(sip_layer, 'method', 'unknown'),
        'call_id': getattr(sip_layer, 'call_id', ''),
        'from': getattr(sip_layer, 'from', ''),
        'to': getattr(sip_layer, 'to', ''),
        'user_agent': getattr(sip_layer, 'user_agent', ''),
    }
    
    method = event['method'].upper() if event['method'] else ''
    
    with call_lock:
        if method == 'INVITE':
            active_calls[event['call_id']] = {
                'call_id': event['call_id'],
                'from': event['from'],
                'to': event['to'],
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'start_time': event['timestamp'],
                'status': 'ringing'
            }
            event['call_status'] = 'ringing'
            
        elif method == 'BYE':
            if event['call_id'] in active_calls:
                call = active_calls.pop(event['call_id'])
                call['end_time'] = event['timestamp']
                call['call_status'] = 'ended'
                event['call_status'] = 'ended'
                try:
                    start = datetime.fromisoformat(call['start_time'])
                    end = datetime.fromisoformat(event['timestamp'])
                    event['duration'] = round((end - start).total_seconds(), 2)
                except Exception:
                    event['duration'] = None
                
        elif method == 'ACK':
            if event['call_id'] in active_calls:
                active_calls[event['call_id']]['call_status'] = 'established'
                event['call_status'] = 'established'
                
        elif method == 'CANCEL':
            if event['call_id'] in active_calls:
                active_calls.pop(event['call_id'])
                event['call_status'] = 'cancelled'
    
    return event

def parse_rtp_stream(pkt):
    if not hasattr(pkt, 'rtp'):
        return None
    
    rtp_layer = pkt.rtp
    src_ip = pkt.ip.src if hasattr(pkt, 'ip') else 'unknown'
    dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else 'unknown'
    
    event = {
        'timestamp': datetime.now().isoformat(),
        'event_type': 'rtp_stream',
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'payload_type': getattr(rtp_layer, 'payload_type', ''),
        'seq_num': getattr(rtp_layer, 'seq', ''),
        'timestamp_field': getattr(rtp_layer, 'timestamp', ''),
        'ssrc': getattr(rtp_layer, 'ssrc', ''),
    }
    
    return event

def capture_voip():
    print(f"Starting VoIP capture on interface {INTERFACE}...")
    print(f"Publishing to Kafka topic: {KAFKA_TOPIC}")
    
    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        bpf_filter='udp port 5060 or udp port 10000-20000',
        output_file=f'/tmp/voip_capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap'
    )
    
    for pkt in capture.sniff_continuously(packet_count=0):
        try:
            event = None
            
            if hasattr(pkt, 'sip'):
                event = parse_sip_packet(pkt)
            elif hasattr(pkt, 'rtp'):
                event = parse_rtp_stream(pkt)
            
            if event:
                print(f"VoIP event: {event['event_type'] if 'event_type' in event else event.get('method', 'unknown')}")
                producer.send(KAFKA_TOPIC, value=event)
                
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

def print_active_calls():
    with call_lock:
        print(f"\n{'='*60}")
        print(f"Active VoIP Calls: {len(active_calls)}")
        print(f"{'='*60}")
        for call_id, call in active_calls.items():
            print(f"Call ID: {call_id}")
            print(f"  From: {call['from']}")
            print(f"  To: {call['to']}")
            print(f"  Status: {call['status']}")
            print(f"  Started: {call['start_time']}")
            print()

if __name__ == '__main__':
    print("VoIP Sensor starting...")
    print(f"Kafka: {KAFKA_BOOTSTRAP}")
    print(f"Topic: {KAFKA_TOPIC}")
    print(f"Interface: {INTERFACE}")
    
    threading.Thread(target=capture_voip, daemon=True).start()
    
    import time
    while True:
        time.sleep(30)
        print_active_calls()
