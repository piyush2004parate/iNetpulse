from django.urls import path
from . import views

urlpatterns = [
    path('start_scan/', views.start_scan, name='start_scan'),
    path('generate_report/', views.generate_report, name='generate_report'),
]
