from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('sniff_packets/', views.sniff_packets, name='sniff_packets'),
    path('start_sniffing/', views.start_sniffing, name='start_sniffing'),
    path('stop_sniffing/', views.stop_sniffing, name='stop_sniffing'),
    path('get_latest_packets/', views.get_latest_packets, name='get_latest_packets'),  # New AJAX endpoint
    path('performance_analysis/', views.speed_performance_analysis, name='speed_performance_analysis'),
    path('traffic-analysis/', views.traffic_analysis, name='traffic_analysis'),
    path('threat-detection/', views.anomaly_detection_view, name='anomaly_detection'),
    path('protocol-detection/', views.protocol_detection, name='protocol_detection'),
    path('setup-alerts/', views.setup_alerts, name='setup_alerts'),
    
]
