from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.exceptions import (
    ValidationError,
    NotFound,
    PermissionDenied,
)
from rest_framework.response import Response
from abc import ABCMeta, abstractmethod

from intel_owl.celery import app as celery_app
from .models import AbstractReport


class PluginActionViewSet(viewsets.ViewSet, metaclass=ABCMeta):
    @property
    @abstractmethod
    def report_model(self):
        raise NotImplementedError()

    def get_object(self, job_id, name):
        """
        overrides drf's get_object
        get plugin report object by name and job_id
        """
        try:
            return self.report_model.objects.get(
                job_id=job_id,
                name=name,
            )
        except self.report_model.DoesNotExist:
            raise NotFound()

    def perform_kill(self, report: AbstractReport):
        """
        performs kill
         override for callbacks after kill operation
        """
        # kill celery task
        celery_app.control.revoke(report.task_id, terminate=True)
        # update report
        report.update_status(AbstractReport.Statuses.KILLED.name)

    def perform_retry(self, report: AbstractReport):
        """
        override to run plugin with these arguments
        """
        plugins_to_execute = [report.name]
        runtime_configuration = {report.name: report.runtime_configuration}
        return plugins_to_execute, runtime_configuration

    @action(detail=False, methods=["patch"])
    def kill(self, request, job_id, name):
        """
        Kill running plugin by closing celery task and marking as killed

        :params url:
         - job_id
         - name (plugin name)
        :returns:
         - 204 - if killed
         - 404 - not found
         - 403 - forbidden, 400 bad request
        """

        # get report object or raise 404
        report = self.get_object(job_id, name)
        if not request.user.has_perm("api_app.change_job", report.job):
            raise PermissionDenied()
        if report.status not in [
            AbstractReport.Status.RUNNING,
            AbstractReport.Status.PENDING,
        ]:
            raise ValidationError({"detail": "Plugin call is not running or pending"})

        self.perform_kill(report)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=["patch"])
    def retry(self, request, job_id, name):
        """
        Retry a plugin run if it failed/was killed previously
         regenerates the args required and starts a new celery task

        :params url:
         - job_id
         - name (plugin name)
        :returns:
         - 204 - if success
         - 404 - not found
         - 403 - forbidden
         - 400 - bad request
        """

        # get report object or raise 404
        report = self.get_object(job_id, name)
        if not request.user.has_perm("api_app.change_job", report.job):
            raise PermissionDenied()
        if report.status not in [
            AbstractReport.Statuses.FAILED.name,
            AbstractReport.Statuses.KILLED.name,
        ]:
            raise ValidationError(
                {"detail": "Plugin call status should be failed or killed"}
            )

        # retry with the same arguments
        self.perform_retry(report)
        return Response(status=status.HTTP_204_NO_CONTENT)
