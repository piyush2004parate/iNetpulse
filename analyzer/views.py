from django.http import JsonResponse
from django.shortcuts import render, redirect
from scapy.all import sniff, TCP, UDP, IP
from threading import Thread
from .models import Packet
import queue
import speedtest
from .models import PerformanceMetrics
from .models import NetworkTraffic, Anomaly
from django.db.models import Count
# Global variables to control sniffing
packet_queue = queue.Queue()
sniff_thread = None
stop_sniffing_flag = False

def home(request):
    return render(request, 'home.html')


def traffic_analysis(request):
    return render(request, 'traffic_analysis.html')


def protocol_detection(request):
    return render(request, 'protocol_detection.html')

def setup_alerts(request):
    return render(request, 'setup_alerts.html')

def packet_callback(packet):
    """Callback to process packets and store in the database."""
    if stop_sniffing_flag:
        return

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

        # Store packet data in the database
        Packet.objects.create(
            destination=destination,
            source=source,
            protocol=protocol,
            packet_type=packet_type,
            segment=segment,
            source_port=source_port,
            destination_port=destination_port,
            sequence=sequence,
            ack=ack
        )

def sniff_packets_in_background():
    """Start sniffing packets in a separate thread."""
    sniff(prn=packet_callback, store=0)

def start_sniffing(request):
    """Start packet sniffing."""
    global sniff_thread, stop_sniffing_flag
    stop_sniffing_flag = False
    if sniff_thread is None or not sniff_thread.is_alive():
        sniff_thread = Thread(target=sniff_packets_in_background)
        sniff_thread.daemon = True
        sniff_thread.start()
    return redirect('sniff_packets')

def stop_sniffing(request):
    """Stop packet sniffing."""
    global stop_sniffing_flag
    stop_sniffing_flag = True
    return redirect('sniff_packets')

def sniff_packets(request):
    """View to display sniffed packets."""
    return render(request, 'sniff_packets.html')

def get_latest_packets(request):
    """View to return latest packets as JSON for AJAX."""
    packets = Packet.objects.all().order_by('-timestamp')[:50]
    packet_data = [{
        'destination': packet.destination,
        'source': packet.source,
        'protocol': packet.protocol,
        'packet_type': packet.packet_type,
        'segment': packet.segment,
        'source_port': packet.source_port,
        'destination_port': packet.destination_port,
        'sequence': packet.sequence,
        'ack': packet.ack,
    } for packet in packets]
    return JsonResponse({'packets': packet_data})


def speed_performance_analysis(request):
    # Run speed test
    st = speedtest.Speedtest()
    
    # Get best server based on ping
    st.get_best_server()
    
    # Perform download and upload speed tests
    download_speed = st.download() / 10**6  # Convert to Mbps
    upload_speed = st.upload() / 10**6  # Convert to Mbps
    
    # Get ping latency
    ping = st.results.ping
    
    # Save the results to the database (optional)
    performance = PerformanceMetrics.objects.create(
        download_speed=download_speed,
        upload_speed=upload_speed,
        ping=ping
    )
    
    # Prepare the data for display
    context = {
        'download_speed': round(download_speed, 2),
        'upload_speed': round(upload_speed, 2),
        'ping': round(ping, 2),
    }
    
    return render(request, 'speed_performance_analysis.html', context)

def detect_anomalies():
    # Example logic for detecting anomalies
    anomalies = []
    
    # Example: detect high traffic volume from a single IP
    high_traffic_ips = NetworkTraffic.objects.values('source_ip').annotate(count=Count('id')).filter(count__gt=100)
    
    for ip in high_traffic_ips:
        anomalies.append(Anomaly(description=f"High traffic from IP {ip['source_ip']}", severity="High"))

    # Save detected anomalies to the database
    for anomaly in anomalies:
        anomaly.save()
    
    return anomalies

def anomaly_detection_view(request):
    anomalies = detect_anomalies()
    context = {
        'anomalies': anomalies
    }
    return render(request, 'anomaly_detection.html', context)

