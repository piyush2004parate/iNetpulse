from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),  # Home page
    path('sniff_packets/', views.sniff_packets, name='sniff_packets'),
    path('start_sniffing/', views.start_sniffing, name='start_sniffing'),
    path('stop_sniffing/', views.stop_sniffing, name='stop_sniffing'),
    path('get_latest_packets/', views.get_latest_packets, name='get_latest_packets'),  # New AJAX endpoint
    path('performance_analysis/', views.speed_performance_analysis, name='speed_performance_analysis'),
    path('traffic_analysis/', views.traffic_analysis, name='traffic_analysis'),  # Traffic analysis page
    path('anomaly_detection/', views.anomaly_detection, name='anomaly_detection'),  # Anomaly detection page
    path('protocol_detection/', views.protocol_detection, name='protocol_detection'),  # Protocol detection page
    path('setup_alerts/', views.setup_alerts, name='setup_alerts'),  # Setup alerts page

    # Anomaly detection specific endpoints
    path('start_scan/', views.anomaly_detection, name='start_scan'),  # Start anomaly scan
    path('generate_report/', views.generate_report, name='generate_report'),  # Generate report after scan
]
