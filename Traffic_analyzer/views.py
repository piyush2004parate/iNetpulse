from django.shortcuts import render
from django.http import JsonResponse
import psutil

# View for rendering the traffic analysis page
def traffic_analysis(request):
    # Retrieve network traffic data using psutil
    traffic_stats = psutil.net_io_counters()

    context = {
        'bytes_sent': traffic_stats.bytes_sent,
        'bytes_recv': traffic_stats.bytes_recv,
        'packets_sent': traffic_stats.packets_sent,
        'packets_recv': traffic_stats.packets_recv,
    }

    # Render the traffic_analysis.html template with the context data
    return render(request, 'analyzer/traffic_analysis.html', context)

# View for returning real-time traffic data as JSON (for use with AJAX)
def traffic_data(request):
    # Get updated network traffic data using psutil
    traffic_stats = psutil.net_io_counters()

    # Prepare the data to send as JSON
    data = {
        'bytes_sent': traffic_stats.bytes_sent,
        'bytes_recv': traffic_stats.bytes_recv,
        'packets_sent': traffic_stats.packets_sent,
        'packets_recv': traffic_stats.packets_recv
    }

    # Return the data as JSON for AJAX calls
    return JsonResponse(data)
