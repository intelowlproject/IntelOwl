# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from abc import ABCMeta, abstractmethod

from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as rfs
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from certego_saas.apps.organization.permissions import IsObjectOwnerOrSameOrgPermission
from intel_owl.celery import app as celery_app

from .models import AbstractReport

logger = logging.getLogger(__name__)


class PluginActionViewSet(viewsets.GenericViewSet, metaclass=ABCMeta):

    permission_classes = [
        IsObjectOwnerOrSameOrgPermission,
    ]

    @property
    @abstractmethod
    def report_model(self):
        raise NotImplementedError()

    def get_object(self, job_id: int, name: str) -> AbstractReport:
        """
        overrides drf's get_object
        get plugin report object by name and job_id
        """
        try:
            obj = self.report_model.objects.get(
                job_id=job_id,
                name=name,
            )
            self.check_object_permissions(self.request, obj)
            return obj
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
        raise NotImplementedError()

    @add_docs(
        description="Kill running plugin by closing celery task and marking as killed",
        request=None,
        responses={
            204: None,
        },
    )
    @action(detail=False, methods=["patch"])
    def kill(self, request, job_id, name):
        logger.info(
            f"kill request from user {request.user} for job_id {job_id}, name {name}"
        )
        # get report object or raise 404
        report = self.get_object(job_id, name)
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
        logger.info(
            f"retry request from user {request.user} for job_id {job_id}, name {name}"
        )
        # get report object or raise 404
        report = self.get_object(job_id, name)
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


@add_docs(
    description="Health Check: if server instance associated with plugin is up or not",
    request=None,
    responses={
        200: inline_serializer(
            name="PluginHealthCheckSuccessResponse",
            fields={
                "status": rfs.BooleanField(allow_null=True),
            },
        ),
    },
)
class PluginHealthCheckAPI(APIView, metaclass=ABCMeta):
    @abstractmethod
    def perform_healthcheck(self, plugin_name: str) -> bool:
        raise NotImplementedError()

    def get(self, request, name):
        logger.info(f"get healthcheck from user {request.user}, name {name}")
        health_status = self.perform_healthcheck(name)
        return Response(data={"status": health_status}, status=status.HTTP_200_OK)
