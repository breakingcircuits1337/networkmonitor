import asyncio
import nmap
from scapy.all import sniff, IP
from dash import Dash, dcc, html, Input, Output
import dash_auth
import plotly.graph_objs as go
import smtplib
import requests
import pygame
from pygtail import Pygtail
import re
from sklearn.ensemble import IsolationForest
import numpy as np
import sqlite3
from datetime import datetime
from elasticsearch import Elasticsearch

# Initialize Dash app with authentication
app = Dash(__name__)
auth = dash_auth.BasicAuth(app, {'admin': 'password'})

# Initialize SQLite database
conn = sqlite3.connect('network_monitor.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS network_data
             (timestamp TEXT, src_ip TEXT, dst_ip TEXT, protocol INTEGER)''')
c.execute('''CREATE TABLE IF NOT EXISTS log_data
             (timestamp TEXT, log_entry TEXT)''')
conn.commit()

# Initialize pygame for audio
pygame.mixer.init()
alert_sound = pygame.mixer.Sound("alert.wav")

# Initialize Elasticsearch
es = Elasticsearch([{'host':'192.168.1.3, 192.168.1.4','port': 9200}])

# Global variables
network_data = []
log_data = []

# Function to detect suspicious patterns
def is_suspicious(src_ip, dst_ip, protocol):
    # Example logic for suspicious activity detection
    return src_ip.startswith("192.168") and dst_ip.startswith("10.")

# Function to send an alert
def alert(message):
    sender = "alert@example.com"
    receiver = "admin@example.com"
    smtp_server = smtplib.SMTP("smtp.gmail.com", 587)
    smtp_server.starttls()
    smtp_server.login(sender, "password")
    smtp_server.sendmail(sender, receiver, message)
    smtp_server.quit()
    
    # Play audible alarm
    alert_sound.play()

# Packet callback function
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        timestamp = datetime.now().isoformat()
        
        # Store in database
        c.execute("INSERT INTO network_data VALUES (?, ?, ?, ?)",
                  (timestamp, src_ip, dst_ip, protocol))
        conn.commit()
        
        # Store in Elasticsearch
        es.index(index='network_data', body={
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol
        })
        
        if is_suspicious(src_ip, dst_ip, protocol):
            alert(f"Suspicious traffic detected from {src_ip} to {dst_ip}")

# Function to analyze logs
def analyze_log(log_file):
    for line in Pygtail(log_file):
        if re.search(r"suspicious_pattern", line):
            timestamp = datetime.now().isoformat()
            c.execute("INSERT INTO log_data VALUES (?, ?)", (timestamp, line))
            conn.commit()
            
            # Store in Elasticsearch
            es.index(index='log_data', body={
                'timestamp': timestamp,
                'log_entry': line
            })
            
            alert("Suspicious log entry detected")

# Function to fetch threat intelligence
def fetch_threat_intelligence():
    response = requests.get("https://api.threatintelligence.com/latest")
    return response.json()

# Function to train anomaly detection model
def train_anomaly_detection():
    c.execute("SELECT src_ip, dst_ip, protocol FROM network_data")
    data = np.array(c.fetchall())
    model = IsolationForest(contamination=0.1)
    model.fit(data)
    return model

# Function to monitor network traffic
async def monitor_network():
    sniff(prn=packet_callback, store=0)

# Function to monitor logs
async def monitor_logs():
    analyze_log("/var/log/syslog")

# Function to discover network devices
def discover_network_devices():
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.0/24', arguments='-sn')
    devices = []
    for host in nm.all_hosts():
        devices.append({
            'ip': host,
            'hostname': nm[host].hostname(),
            'state': nm[host].state()
        })
    return devices

# Function to update dashboard
@app.callback(
    [Output('live-graph', 'figure'),
     Output('anomaly-graph', 'figure'),
     Output('device-list', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_graphs(n):
    # Network traffic graph
    c.execute("SELECT src_ip, dst_ip FROM network_data ORDER BY timestamp DESC LIMIT 100")
    recent_data = c.fetchall()
    traffic_data = go.Scatter(
        x=[x[0] for x in recent_data],
        y=[x[1] for x in recent_data],
        mode='markers'
    )
    traffic_layout = go.Layout(title='Recent Network Traffic')
    
    # Anomaly detection graph
    model = train_anomaly_detection()
    c.execute("SELECT src_ip, dst_ip, protocol FROM network_data ORDER BY timestamp DESC LIMIT 1000")
    data = np.array(c.fetchall())
    anomaly_scores = model.decision_function(data)
    anomaly_data = go.Scatter(
        x=range(len(anomaly_scores)),
        y=anomaly_scores,
        mode='lines'
    )
    anomaly_layout = go.Layout(title='Anomaly Scores')
    
    # Network devices list
    devices = discover_network_devices()
    device_list = html.Ul([html.Li(f"{device['hostname']} ({device['ip']}) - {device['state']}") for device in devices])
    
    return ({'data': [traffic_data], 'layout': traffic_layout},
            {'data': [anomaly_data], 'layout': anomaly_layout},
            device_list)

# Main function
async def main():
    await asyncio.gather(
        monitor_network(),
        monitor_logs()
    )

# Dash layout
app.layout = html.Div(children=[
    html.H1(children='Real-Time Network Threat Monitoring'),
    dcc.Tabs(id="tabs", children=[
        dcc.Tab(label='Easy Mode', children=[
            html.Div(children=[
                html.H2(children='Network Traffic'),
                dcc.Graph(id='live-graph'),
                dcc.Interval(
                    id='interval-component',
                    interval=5*1000,  # in milliseconds
                    n_intervals=0
                )
            ])
        ]),
        dcc.Tab(label='Advanced Mode', children=[
            html.Div(children=[
                html.H2(children='Network Traffic'),
                dcc.Graph(id='live-graph'),
                html.H2(children='Anomaly Detection'),
                dcc.Graph(id='anomaly-graph'),
                dcc.Interval(
                    id='interval-component',
                    interval=5*1000,  # in milliseconds
                    n_intervals=0
                )
            ])
        ]),
        dcc.Tab(label='Elite Mode', children=[
            html.Div(children=[
                html.H2(children='Network Traffic'),
                dcc.Graph(id='live-graph'),
                html.H2(children='Anomaly Detection'),
                dcc.Graph(id='anomaly-graph'),
                html.H2(children='Network Devices'),
                html.Div(id='device-list'),
                dcc.Interval(
                    id='interval-component',
                    interval=5*1000,  # in milliseconds
                    n_intervals=0
                )
            ])
        ])
    ])
])

if __name__ == '__main__':
    asyncio.run(main())
    app.run_server(debug=True)

