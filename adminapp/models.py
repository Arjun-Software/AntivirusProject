import os
from django.http import response
from django.db import models
from django.utils.timezone import now
# Create your models here.
# your_app_name/models.py


class finalboth_jagah(models.Model):
    mac_address = models.CharField(max_length=17, unique=True, null=True, blank=True)  # Allow null and blank
    first_name = models.CharField(max_length=100, null=True, blank=True)  # Allow null and blank
    last_name = models.CharField(max_length=100, null=True, blank=True)  # Allow null and blank
    phone = models.CharField(max_length=20, null=True, blank=True)  # Allow null and blank
    registered_on =  models.DateTimeField(default=now)
    key_id = models.CharField(max_length=100)
    licence_key = models.CharField(max_length=255)
    
    def __str__(self):
        return f"{self.licence_key}"
    class Meta:
        db_table = 'finalboth_licencekey'
    
from django.utils import timezone

# class LicenceKey(models.Model):
#     mac_address = models.CharField(max_length=17, unique=True)  # MAC address format
#     key_id = models.CharField(max_length=100)
#     licence_key = models.CharField(max_length=255)
#     first_name = models.CharField(max_length=100)
#     last_name = models.CharField(max_length=100)
#     phone = models.CharField(max_length=20)
#     registered_on = models.DateTimeField(default=timezone.localtime)  # Set the timezone to Asia/Kolkata
    
#     def __str__(self):
#         return f"{self.mac_address} - {self.key_id}"
    
#     class Meta:
#         db_table = 'paxapp_licencekey'


from django.db import transaction
class LicenceKey(models.Model):
    mac_address = models.CharField(max_length=500, unique=True)  # MAC address format
    key_id = models.CharField(max_length=500)
    licence_key = models.CharField(max_length=500)
    first_name = models.CharField(max_length=500)
    last_name = models.CharField(max_length=500)
    phone = models.CharField(max_length=500)
    registered_on  = models.DateTimeField(max_length=500, null=True, blank=True)
    valid_upto = models.CharField(max_length=500 , null=True,blank=True)
    key_status = models.CharField(max_length=500, default='Active')
    print("-----key_status-------",key_status)
    def save(self, *args, **kwargs):
        try:
            # Save to the default database
            with transaction.atomic(using='default'):
                super().save(*args, **kwargs)
            with transaction.atomic(using='sqlite3'):
                super(LicenceKey, self).save(using='sqlite3', *args, **kwargs)
        except Exception as e:
            # Handle errors and ensure data consistency
            print(f"Error saving LicenceKey: {e}")
            raise e

    def __str__(self):
        return f"{self.mac_address} - {self.key_id}"
    
    class Meta:
        db_table = 'LicenceKey'
