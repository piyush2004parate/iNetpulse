from django.urls import path
from . import views

urlpatterns = [
    path('traffic-analysis/', views.traffic_analysis, name='traffic_analysis'),
    path('traffic-data/', views.traffic_data, name='traffic_data'),  # New view for real-time data
]
