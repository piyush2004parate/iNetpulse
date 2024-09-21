# Generated by Django 5.1.1 on 2024-09-21 13:18

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Anomaly',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('description', models.TextField()),
                ('severity', models.CharField(max_length=10)),
            ],
        ),
        migrations.CreateModel(
            name='NetworkTraffic',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('source_ip', models.GenericIPAddressField()),
                ('destination_ip', models.GenericIPAddressField()),
                ('protocol', models.CharField(max_length=10)),
                ('source_port', models.IntegerField()),
                ('destination_port', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='Packet',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('destination', models.CharField(max_length=255)),
                ('source', models.CharField(max_length=255)),
                ('protocol', models.CharField(max_length=10)),
                ('packet_type', models.CharField(max_length=10)),
                ('segment', models.CharField(max_length=20)),
                ('source_port', models.CharField(max_length=10)),
                ('destination_port', models.CharField(max_length=10)),
                ('sequence', models.CharField(blank=True, max_length=20, null=True)),
                ('ack', models.CharField(blank=True, max_length=20, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='PerformanceMetrics',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('download_speed', models.FloatField()),
                ('upload_speed', models.FloatField()),
                ('ping', models.FloatField()),
            ],
        ),
    ]
