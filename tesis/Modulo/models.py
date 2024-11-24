from django.db import models

class ComputerProperties(models.Model):
    computer_id = models.IntegerField(unique=True)
    name = models.CharField(max_length=255)
    lab = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    operating_system = models.CharField(max_length=255)
    disk = models.CharField(max_length=255)
    motherboard = models.CharField(max_length=255)
    ram = models.CharField(max_length=255)
    last_update = models.DateTimeField()
    antivirus = models.CharField(max_length=255)
    antivirus_enabled = models.BooleanField(default=False)
    antivirus_updated = models.BooleanField(default=False)
    firewall = models.CharField(max_length=255)
    firewall_enabled = models.BooleanField(default=False)
    browser = models.CharField(max_length=255, default="Firefox")
    domain = models.CharField(max_length=255)

class User(models.Model):
    user_id = models.IntegerField(unique=True)
    name = models.CharField(max_length=255)
    password = models.CharField(max_length=255)  # Asegúrate de hashear la contraseña antes de guardarla

class Rule(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()

    def __str__(self):
        return self.name


class Monitoreo(models.Model):
    date_checked = models.DateTimeField(auto_now_add=True)
    computers_monitored = models.ManyToManyField(ComputerProperties)
    incumplimientos_detected = models.JSONField(default=list)  # Usamos JSONField para almacenar los incumplimientos

    def __str__(self):
        return f"Monitoreo {self.id} - {self.date_checked}"
