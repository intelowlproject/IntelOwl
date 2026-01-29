# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger

from rest_framework.permissions import BasePermission

logger = getLogger(__name__)


class IsObjectOwnerPermission(BasePermission):
    """
    Permission class to check if the requesting user is the owner of the object.

    Methods:
        has_object_permission(request, view, obj): Checks if the requesting user is the owner of the object.
    """

    @staticmethod
    def has_object_permission(request, view, obj):
        """
        Checks if the requesting user has permission to access the object.

        Args:
            request: The HTTP request object.
            view: The view object.
            obj: The object to check ownership of.

        Returns:
            bool: True if the requesting user is the owner of the object, False otherwise.
        """
        obj_owner = getattr(obj, "owner", None)
        if not obj_owner:
            return False
        return obj_owner == request.user


class IsObjectSameOrgPermission(BasePermission):
    """
    Permission class to check if the requesting user and the object owner belong to the same organization.

    Methods:
        has_object_permission(request, view, obj): Checks if the requesting user and the object owner are in the same organization.
    """

    @staticmethod
    def has_object_permission(request, view, obj):
        """
        Checks if the requesting user has permission to access the object based on organizational membership.

        Args:
            request: The HTTP request object.
            view: The view object.
            obj: The object to check organizational membership for.

        Returns:
            bool: True if the requesting user and the object owner are in the same organization, False otherwise.
        """
        return (
            obj.owner.has_membership()
            and request.user.has_membership()
            and obj.owner.membership.organization_id == request.user.membership.organization_id
        )


IsObjectOwnerOrSameOrgPermission = IsObjectSameOrgPermission | IsObjectOwnerPermission


class IsObjectAdminPermission(BasePermission):
    """
    Permission class to check if the requesting user is an admin of the organization that owns the object.

    Methods:
        has_object_permission(request, view, obj): Checks if the requesting user is an admin in the object's organization.
    """

    @staticmethod
    def has_object_permission(request, view, obj):
        """
        Checks if the requesting user has admin permission to access the object.

        Args:
            request: The HTTP request object.
            view: The view object.
            obj: The object to check admin permission for.

        Returns:
            bool: True if the requesting user is an admin of the object's organization, False otherwise.
        """
        obj_owner = getattr(obj, "owner", None)
        # if the object was not made for an organization, we return false
        if not obj_owner or not obj_owner.has_membership():
            return False
        else:
            # if we are admin we can e have to check that is our org
            return (
                request.user.has_membership()
                and request.user.membership.is_admin
                and obj_owner.membership.organization == request.user.membership.organization
            )


class isPluginActionsPermission(BasePermission):
    @staticmethod
    def has_object_permission(request, view, obj):
        # only an admin or superuser can update or delete plugins
        if request.user.has_membership():
            return request.user.membership.is_admin
        else:
            return request.user.is_superuser
