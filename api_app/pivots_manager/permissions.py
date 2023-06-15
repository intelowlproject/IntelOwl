from rest_framework.permissions import BasePermission


class PivotOwnerPermission(BasePermission):
    def has_object_permission(self, request, view, obj):
        return (
            obj.starting_job.user.pk == request.user.pk
            and obj.ending_job.user.pk == request.user.pk
        )
