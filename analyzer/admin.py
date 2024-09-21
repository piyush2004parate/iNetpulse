from django.contrib import admin
from .models import Packet
from .models import PerformanceMetrics

admin.site.register(Packet)
admin.site.register(PerformanceMetrics)
