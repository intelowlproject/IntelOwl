from rest_framework.permissions import BasePermission


class PivotOwnerPermission(BasePermission):
    @staticmethod
    def has_object_permission(request, view, obj):
        return obj.starting_job.user.pk == request.user.pk and obj.ending_job.user.pk == request.user.pk


class PivotActionsPermission(BasePermission):
    @staticmethod
    def has_object_permission(request, view, obj):
        # only an admin or superuser can update or delete pivots
        if request.user.has_membership():
            return request.user.membership.is_admin
        else:
            return request.user.is_superuser
