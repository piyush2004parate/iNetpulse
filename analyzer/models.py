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
    timestamp = models.DateTimeField(auto_now_add=True)
    download_speed = models.FloatField()  # in Mbps
    upload_speed = models.FloatField()    # in Mbps
    ping = models.FloatField()            # in ms

    def __str__(self):
        return f"Performance on {self.timestamp}"


class NetworkTraffic(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    protocol = models.CharField(max_length=10)
    source_port = models.IntegerField()
    destination_port = models.IntegerField()

    def __str__(self):
        return f"{self.timestamp} - {self.source_ip} to {self.destination_ip}"

class Anomaly(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    description = models.TextField()
    severity = models.CharField(max_length=10)

    def __str__(self):
        return f"{self.timestamp} - {self.description} ({self.severity})"
    




