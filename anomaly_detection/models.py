from django.db import models

class AnomalyLog(models.Model):
    anomaly_type = models.CharField(max_length=50)
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.anomaly_type}"
