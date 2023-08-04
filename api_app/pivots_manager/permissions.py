from rest_framework.permissions import BasePermission


class PivotOwnerPermission(BasePermission):
    @staticmethod
    def has_object_permission(request, view, obj):
        return (
            obj.starting_job.user.pk == request.user.pk
            and obj.ending_job.user.pk == request.user.pk
        )
