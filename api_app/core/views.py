from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.exceptions import (
    ValidationError,
    NotFound,
    PermissionDenied,
)
from rest_framework.response import Response
from drf_spectacular.utils import (
    extend_schema as add_docs,
)
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
        report.update_status(AbstractReport.Status.KILLED)

    def perform_retry(self, report: AbstractReport):
        """
        override to run plugin with these arguments
        """
        plugins_to_execute = [report.name]
        runtime_configuration = {report.name: report.runtime_configuration}
        return plugins_to_execute, runtime_configuration

    @add_docs(
        description="Kill running plugin by closing celery task and marking as killed",
        request=None,
        responses={
            204: None,
        },
    )
    @action(detail=False, methods=["patch"])
    def kill(self, request, job_id, name):
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

    @add_docs(
        description="Retry a plugin run if it failed/was killed previously",
        request=None,
        responses={
            204: None,
        },
    )
    @action(detail=False, methods=["patch"])
    def retry(self, request, job_id, name):
        # get report object or raise 404
        report = self.get_object(job_id, name)
        if not request.user.has_perm("api_app.change_job", report.job):
            raise PermissionDenied()
        if report.status not in [
            AbstractReport.Status.FAILED,
            AbstractReport.Status.KILLED,
        ]:
            raise ValidationError(
                {"detail": "Plugin call status should be failed or killed"}
            )

        # retry with the same arguments
        self.perform_retry(report)
        return Response(status=status.HTTP_204_NO_CONTENT)
