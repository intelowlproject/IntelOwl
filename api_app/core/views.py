from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.exceptions import (
    ValidationError,
    PermissionDenied,
)
from rest_framework.response import Response
from abc import ABCMeta, abstractmethod

from intel_owl.celery import app as celery_app
from .models import AbstractReport


class PluginActionViewSet(viewsets.ViewSet, metaclass=ABCMeta):
    @abstractmethod
    def get_object(self, job_id, name) -> AbstractReport:
        """
        overrides drf's get_object
        get plugin report object by name and job_id
        """
        raise NotImplementedError()

    @abstractmethod
    def _post_kill(self, report):
        """
        callback executed post plugin kill
        """
        raise NotImplementedError()

    @action(detail=False, methods=["patch"])
    def kill(self, request, job_id, name):
        """
        Kill running plugin by closing celery task and marking as killed

        :params url:
         - job_id
         - name (plugin name)
        :returns:
         - 200 - if killed
         - 404 - not found
         - 403 - forbidden, 400 bad request
        """

        # get report object or raise 404
        report = self.get_object(job_id, name)
        if not request.user.has_perm("api_app.change_job", report.job):
            raise PermissionDenied()
        if report.status not in [
            AbstractReport.Statuses.RUNNING.name,
            AbstractReport.Statuses.PENDING.name,
        ]:
            raise ValidationError({"detail": "Plugin call is not running or pending"})

        # kill celery task
        celery_app.control.revoke(report.task_id, terminate=True)
        # update report
        report.status = AbstractReport.Statuses.KILLED.name
        report.save(update_fields=["status"])
        # execute callback post kill
        self._post_kill(report)

        return Response(status=status.HTTP_200_OK)
