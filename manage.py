import os
import sys
from scapy.all import sniff, TCP, UDP, IP
from threading import Thread
import queue


# Queue to store packet data
packet_queue = queue.Queue()

def packet_callback(packet):
    """Callback function to process each packet."""
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        source = ip_layer.src
        destination = ip_layer.dst
        protocol = "IPv4"
        packet_type = "N/A"
        segment = "N/A"
        source_port = "N/A"
        destination_port = "N/A"
        sequence = "N/A"
        ack = "N/A"
        
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            packet_type = "TCP"
            segment = tcp_layer.seq
            source_port = tcp_layer.sport
            destination_port = tcp_layer.dport
            sequence = tcp_layer.seq
            ack = tcp_layer.ack

        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            packet_type = "UDP"
            source_port = udp_layer.sport
            destination_port = udp_layer.dport

        # Add packet data to the queue
        packet_queue.put({
            'destination': destination,
            'source': source,
            'protocol': protocol,
            'packet_type': packet_type,
            'segment': segment,
            'source_port': source_port,
            'destination_port': destination_port,
            'sequence': sequence,
            'ack': ack
        })

def sniff_packets_in_background():
    """Start sniffing packets in a separate thread."""
    sniff(prn=packet_callback, store=0)

def main():
    """Run administrative tasks and start sniffing packets."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'inetpulse.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    # Start packet sniffing in a separate thread
    sniff_thread = Thread(target=sniff_packets_in_background)
    sniff_thread.daemon = True
    sniff_thread.start()

    # Execute Django command-line utility
    execute_from_command_line(sys.argv)

if __name__ == '__main__':
    main()
