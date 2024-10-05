from django.shortcuts import render
from django.http import JsonResponse
import psutil

# View for rendering the traffic analysis page
def traffic_analysis(request):
    # Retrieve initial network traffic data using psutil
    traffic_stats = psutil.net_io_counters()
    connections = psutil.net_connections(kind='inet')  # Get active internet connections

    # Prepare connections for rendering in the template
    connection_data = []
    for conn in connections:
        local_address = {'ip': conn.laddr[0], 'port': conn.laddr[1]}
        remote_address = {'ip': conn.raddr[0], 'port': conn.raddr[1]} if conn.raddr else None
        connection_data.append({
            'local_address': local_address,
            'remote_address': remote_address
        })

    context = {
        'bytes_sent': traffic_stats.bytes_sent,
        'bytes_recv': traffic_stats.bytes_recv,
        'packets_sent': traffic_stats.packets_sent,
        'packets_recv': traffic_stats.packets_recv,
        'connections': connection_data,  # Pass structured connection data to context
    }

    # Render the traffic_analysis.html template with the context data
    return render(request, 'analyzer/traffic_analysis.html', context)

# View for returning real-time traffic data as JSON (for use with AJAX)
def traffic_data(request):
    try:
        # Get updated network traffic data using psutil
        traffic_stats = psutil.net_io_counters()
        connections = psutil.net_connections(kind='inet')  # Get active internet connections

        # Prepare the data to send as JSON
        data = {
            'bytes_sent': traffic_stats.bytes_sent,
            'bytes_recv': traffic_stats.bytes_recv,
            'packets_sent': traffic_stats.packets_sent,
            'packets_recv': traffic_stats.packets_recv,
            'connections': [
                {
                    'local_address': {'ip': conn.laddr[0], 'port': conn.laddr[1]},
                    'remote_address': {'ip': conn.raddr[0], 'port': conn.raddr[1]} if conn.raddr else None
                }
                for conn in connections
            ]  # Extract local and remote addresses
        }

        # Return the data as JSON for AJAX calls
        return JsonResponse(data)
    
    except Exception as e:
        # Handle exceptions and return an error message
        return JsonResponse({'error': str(e)}, status=500)
