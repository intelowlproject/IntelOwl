# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger

from rest_framework.permissions import BasePermission

logger = getLogger(__name__)


class IsObjectOwnerPermission(BasePermission):
    @staticmethod
    def has_object_permission(request, view, obj):
        obj_owner = getattr(obj, "owner", None)
        if not obj_owner:
            return False
        return obj_owner == request.user


class IsObjectSameOrgPermission(BasePermission):
    @staticmethod
    def has_object_permission(request, view, obj):
        return (
            obj.owner.has_membership()
            and request.user.has_membership()
            and obj.owner.membership.organization_id
            == request.user.membership.organization_id
        )


IsObjectOwnerOrSameOrgPermission = IsObjectSameOrgPermission | IsObjectOwnerPermission


class IsObjectAdminPermission(BasePermission):
    @staticmethod
    def has_object_permission(request, view, obj):
        obj_owner = getattr(obj, "owner", None)
        # if the object was not made for an organization, we return false
        if not obj_owner or not obj_owner.has_membership():
            return False
        else:
            # if we are admin we can e have to check that is our org
            return (
                request.user.has_membership()
                and request.user.membership.is_admin
                and obj_owner.membership.organization
                == request.user.membership.organization
            )
