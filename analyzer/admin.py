from django.contrib import admin
from .models import Packet
from .models import PerformanceMetrics
from .models import NetworkTraffic
from .models import Anomaly


admin.site.register(Packet)
admin.site.register(PerformanceMetrics)
admin.site.register(NetworkTraffic)
admin.site.register(Anomaly)