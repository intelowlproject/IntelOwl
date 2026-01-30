# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from api_app.investigations_manager.models import Investigation
from api_app.serializers import ModelWithOwnershipSerializer
from api_app.serializers.job import JobTreeSerializer


class InvestigationSerializer(ModelWithOwnershipSerializer, rfs.ModelSerializer):
    tags = rfs.ListField(child=rfs.CharField(read_only=True), read_only=True, default=[])
    tlp = rfs.CharField(read_only=True)
    total_jobs = rfs.IntegerField(read_only=True)
    jobs = rfs.PrimaryKeyRelatedField(many=True, read_only=True)
    status = rfs.CharField(read_only=True)
    owner = rfs.HiddenField(default=rfs.CurrentUserDefault())

    class Meta:
        model = Investigation
        fields = rfs.ALL_FIELDS


class InvestigationTreeSerializer(rfs.ModelSerializer):
    class Meta:
        model = Investigation
        fields = ["name", "owner", "jobs"]

    jobs = JobTreeSerializer(many=True)
