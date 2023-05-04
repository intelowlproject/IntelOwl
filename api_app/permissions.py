# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger

from rest_framework.permissions import BasePermission

logger = getLogger(__name__)


class IsObjectRealOwnerPermission(BasePermission):
    def has_object_permission(self, request, view, obj):
        if obj_owner := getattr(obj, "owner", None):
            return obj_owner == request.user
        return False
