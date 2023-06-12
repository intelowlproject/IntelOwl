from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer
from api_app.pivot_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig


class PivotConfigSerializer(AbstractConfigSerializer):
    name = rfs.CharField()
    config = rfs.PrimaryKeyRelatedField(read_only=True)
    field = rfs.CharField()
    playbook = rfs.PrimaryKeyRelatedField(queryset=PlaybookConfig.objects.all())

    class Meta:
        model = PivotConfig
