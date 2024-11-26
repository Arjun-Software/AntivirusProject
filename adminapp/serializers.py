from rest_framework import serializers
from .models import LicenceKey

class LicenceKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = LicenceKey
        fields = ['id', 'mac_address', 'first_name', 'last_name', 'phone', 'registered_on', 'key_id', 'licence_key']
