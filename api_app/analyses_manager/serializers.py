# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from api_app.analyses_manager.models import Analysis
from api_app.serializers import ModelWithOwnershipSerializer
from api_app.serializers.job import JobTreeSerializer


class AnalysisSerializer(ModelWithOwnershipSerializer, rfs.ModelSerializer):
    tags = rfs.ListField(
        child=rfs.CharField(read_only=True), read_only=True, default=[]
    )
    tlp = rfs.CharField(read_only=True)
    total_jobs = rfs.IntegerField(read_only=True)
    jobs = rfs.PrimaryKeyRelatedField(many=True, read_only=True)
    status = rfs.CharField(read_only=True)
    owner = rfs.HiddenField(default=rfs.CurrentUserDefault())

    class Meta:
        model = Analysis
        fields = rfs.ALL_FIELDS


class AnalysisTreeSerializer(rfs.ModelSerializer):
    class Meta:
        model = Analysis
        fields = ["name", "owner", "jobs"]

    jobs = JobTreeSerializer(many=True)
