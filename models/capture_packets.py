from scapy.all import sniff, IP, TCP, UDP
import pandas as pd

packets_data = []

def packet_callback(packet):
    if IP in packet:
        packet_info = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'len': packet[IP].len,
            'ttl': packet[IP].ttl,
        }
        if TCP in packet:
            packet_info['protocol'] = 'TCP'
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
        elif UDP in packet:
            packet_info['protocol'] = 'UDP'
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
        packets_data.append(packet_info)

# Sniff packets for 30 seconds (or more for better dataset)
sniff(timeout=30, prn=packet_callback)

# Convert to DataFrame
df = pd.DataFrame(packets_data)

# Save to CSV
df.to_csv('network_traffic_data.csv', index=False)
print(f"Captured {len(df)} packets and saved to network_traffic_data.csv")
