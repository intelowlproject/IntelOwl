# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers as rfs

from certego_saas.models import User
from certego_saas.user.serializers import (
    UserAccessSerializer as CertegoUserAccessSerializer,
)

from ..models import Job

__all__ = [
    "UserAccessSerializer",
]


class _AccessSerializer(rfs.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "total_submissions",
            "month_submissions",
        )

    # User <-> Job stats
    total_submissions = rfs.SerializerMethodField()
    month_submissions = rfs.SerializerMethodField()

    @staticmethod
    def get_total_submissions(obj: User) -> int:
        return Job.user_total_submissions(obj)

    @staticmethod
    def get_month_submissions(obj: User) -> int:
        return Job.user_month_submissions(obj)


class UserAccessSerializer(CertegoUserAccessSerializer):
    class Meta:
        model = User
        fields = (
            "user",
            "access",
        )

    access = rfs.SerializerMethodField()

    @staticmethod
    def get_access(obj: User) -> dict:
        return _AccessSerializer(instance=obj).data
