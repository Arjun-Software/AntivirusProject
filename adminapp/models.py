import os
from django.http import response
from django.db import models

# Create your models here.
# your_app_name/models.py

from django.db import models

class FileScan(models.Model):
    file_name = models.CharField(max_length=255)
    scan_result = models.JSONField()
    scanned_at = models.DateTimeField(auto_now_add=True)

# In your scan_file method
from adminapp.models import FileScan

def scan_file(self, file_path):
    # ... [existing scan logic]
    if response.status_code == 200:
        scan_result = response.json()
        FileScan.objects.create(file_name=os.path.basename(file_path), scan_result=scan_result)



class BlockedProgram(models.Model):
    program_path = models.CharField(max_length=255, unique=True)
    blocked_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        db_table = "adminapp_blockedprogram"
    def __str__(self):
        return self.program_path