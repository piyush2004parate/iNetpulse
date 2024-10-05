from django.db import models

class Packet(models.Model):
    destination = models.CharField(max_length=255)
    source = models.CharField(max_length=255)
    protocol = models.CharField(max_length=10)
    packet_type = models.CharField(max_length=10)
    segment = models.CharField(max_length=20)
    source_port = models.CharField(max_length=10)
    destination_port = models.CharField(max_length=10)
    sequence = models.CharField(max_length=20, null=True, blank=True)
    ack = models.CharField(max_length=20, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Packet from {self.source} to {self.destination}"
    

class PerformanceMetrics(models.Model):
    download_speed = models.FloatField(default=0.0)  # Assuming 0 is a valid default
    upload_speed = models.FloatField(default=0.0)    # Assuming 0 is a valid default
    ping = models.FloatField(default=0.0)             # Assuming 0 is a valid default
    packet_loss = models.FloatField(default=0.0)     # Assuming 0 is a valid default
    jitter = models.FloatField(default=0.0, null=True)  # Default to 0.0
    latency = models.FloatField(default=0.0)          # Assuming 0 is a valid default
    throughput = models.FloatField(default=0.0)       # Assuming 0 is a valid default
    connection_time = models.FloatField(default=0.0, null=True)  # Default to 0.0
    max_throughput = models.FloatField(default=0.0)   # Assuming 0 is a valid default
    average_throughput = models.FloatField(default=0.0, null=True)  # Default to 0.0
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Performance on {self.timestamp}"





    




