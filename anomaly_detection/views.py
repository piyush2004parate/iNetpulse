import threading
from scapy.all import sniff, IP, TCP, UDP, DNS
from django.http import JsonResponse
from joblib import load
import numpy as np

# Global variables to track metrics
packet_count = 0
bandwidth_usage = {}
port_scan_attempts = {}
unusual_destinations = {}
dns_anomalies = []
death_packets_count = 0
anomalies_report = []

# Load pre-trained model (if using a model for anomaly detection)
clf = load("C:\Users\Admin\Downloads\inetpulse\inetpulse\inetpulse\inetpulse\models\isolation_forest_model.pkl")

def start_scan(request):
    """Start the network packet scan for 30 seconds."""
    if request.method == "POST":
        global packet_count, bandwidth_usage, port_scan_attempts, unusual_destinations, dns_anomalies, death_packets_count, anomalies_report
        
        # Reset tracking variables
        packet_count = 0
        bandwidth_usage.clear()
        port_scan_attempts.clear()
        unusual_destinations.clear()
        dns_anomalies = []
        death_packets_count = 0
        anomalies_report = []

        # Run the scan in a separate thread to avoid blocking
        scan_thread = threading.Thread(target=sniff, kwargs={'timeout': 30, 'prn': packet_callback, 'iface': 'eth0'})
        scan_thread.start()

        return JsonResponse({"message": "Scan started! Results will be logged."})

def packet_callback(packet):
    """Callback for each captured packet."""
    global packet_count
    packet_count += 1
    analyze_packet(packet)

def analyze_packet(packet):
    """Analyze each packet for anomalies."""
    try:
        detect_death_packets(packet)
        detect_bandwidth_spikes(packet)
        detect_port_scanning(packet)
        detect_unusual_destinations(packet)
        detect_anomalous_dns_queries(packet)
    except Exception as e:
        print(f"Error analyzing packet: {e}")

# Anomaly detection functions

def detect_death_packets(packet):
    """Detect abnormal packet terminations."""
    global death_packets_count
    if packet.haslayer(TCP) and packet[TCP].flags == 'R':  # Check for TCP reset flags
        death_packets_count += 1

def detect_bandwidth_spikes(packet):
    """Track bandwidth usage for potential spikes."""
    global bandwidth_usage
    src_ip = packet[IP].src
    packet_size = len(packet)
    if src_ip in bandwidth_usage:
        bandwidth_usage[src_ip] += packet_size
    else:
        bandwidth_usage[src_ip] = packet_size

def detect_port_scanning(packet):
    """Detect port scanning attempts."""
    global port_scan_attempts
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
        if src_ip in port_scan_attempts:
            if dst_port not in port_scan_attempts[src_ip]:
                port_scan_attempts[src_ip].append(dst_port)
        else:
            port_scan_attempts[src_ip] = [dst_port]

def detect_unusual_destinations(packet):
    """Track connections to unknown destinations."""
    global unusual_destinations
    known_ips = ['192.168.1.1', '192.168.1.2']  # Known internal IPs
    dst_ip = packet[IP].dst
    if dst_ip not in known_ips:
        if dst_ip in unusual_destinations:
            unusual_destinations[dst_ip] += 1
        else:
            unusual_destinations[dst_ip] = 1

def detect_anomalous_dns_queries(packet):
    """Detect unusual DNS queries."""
    global dns_anomalies
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
        dns_anomalies.append(packet[DNS].qd.qname.decode())

# Generate the report after the scan completes
def generate_report():
    """Generate the anomaly report after the scan completes."""
    global packet_count, bandwidth_usage, port_scan_attempts, unusual_destinations, dns_anomalies, death_packets_count, anomalies_report
    
    report = {
        "Total Packets": packet_count,
        "Death Packets": death_packets_count,
        "Bandwidth Usage": bandwidth_usage,
        "Port Scan Attempts": port_scan_attempts,
        "Unusual Traffic Destinations": unusual_destinations,
        "Anomalous DNS Queries": dns_anomalies
    }
    
    # Save or display the report as needed
    anomalies_report.append(report)
    return JsonResponse(report)
