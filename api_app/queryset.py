import uuid
from typing import Generator

from celery.canvas import Signature
from django.db import models
from django.db.models import Exists, F, IntegerField, OuterRef, Q, QuerySet
from django.db.models.aggregates import Count
from django.db.models.functions import Cast
from django.db.models.lookups import Exact

from api_app.choices import TLP
from api_app.models import Job, PythonConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.user.models import User


class CleanOnCreateQuerySet(models.QuerySet):
    def create(self, **kwargs):
        obj = self.model(**kwargs)
        obj: models.Model
        obj.clean()
        self._for_write = True
        obj.save(force_insert=True, using=self.db)
        return obj


class AbstractConfigQuerySet(CleanOnCreateQuerySet):
    def annotate_runnable(self, user: User = None) -> QuerySet:
        qs = self.filter(
            pk=OuterRef("pk"),
        ).exclude(disabled=True)

        if user and user.has_membership():
            qs = qs.exclude(
                disabled_in_organization=user.membership.organization,
            )
        return self.annotate(runnable=Exists(qs))


class JobQuerySet(CleanOnCreateQuerySet):
    def visible_for_user(self, user: User) -> QuerySet:
        """
        User has access to:
        - jobs with TLP = CLEAR or GREEN
        - jobs with TLP = AMBER or RED and
        created by a member of their organization.
        """
        if user.has_membership():
            user_query = Q(user=user) | Q(
                user__membership__organization_id=user.membership.organization_id
            )
        else:
            user_query = Q(user=user)
        query = Q(tlp__in=[TLP.CLEAR, TLP.GREEN]) | (
            Q(tlp__in=[TLP.AMBER, TLP.RED]) & (user_query)
        )
        return self.filter(query)


class ParameterQuerySet(CleanOnCreateQuerySet):
    def configured_for_user(self, user: User) -> QuerySet:
        from api_app.models import PluginConfig

        return self.annotate(
            configured=Exists(
                PluginConfig.objects.filter(parameter=OuterRef("pk")).visible_for_user(
                    user
                )
            )
        )


class PluginConfigQuerySet(CleanOnCreateQuerySet):
    def visible_for_user(self, user: User = None) -> QuerySet:
        if user:
            # User-level custom configs should override organization-level configs,
            # we need to get the organization-level configs, if any, first.
            try:
                membership = Membership.objects.get(user=user)
            except Membership.DoesNotExist:
                # If user is not a member of any organization,
                # we don't need to do anything.
                return self.filter(Q(owner=user) | Q(owner__isnull=True))
            else:
                return self.filter(
                    (Q(for_organization=True) & Q(owner=membership.organization.owner))
                    | Q(owner=user)
                    | Q(owner__isnull=True)
                )
        else:
            return self.filter(owner__isnull=True)


class PythonConfigQuerySet(AbstractConfigQuerySet):
    def annotate_configured(self, user: User = None) -> QuerySet:
        from api_app.models import Parameter

        return (
            self.annotate(
                required_params=Count(
                    Parameter.objects.filter(
                        analyzer_config=OuterRef("pk"), required=True
                    ).values_list("pk", flat=True)
                )
            )
            .annotate(
                configured_required_params=Count(
                    Parameter.objects.filter(analyzer_config=OuterRef("pk"))
                    .configured_for_user(user)
                    .filter(configured=True, required=True)
                    .values_list("pk", flat=True)
                )
            )
            .annotate(
                configured=Exact(
                    F("required_params") - F("configured_required_params"), 0
                )
            )
        )

    def annotate_runnable(self, user: User = None) -> QuerySet:
        qs = self.annotate_configured(user)
        return (
            super(PythonConfigQuerySet, qs)
            .annotate_runnable()
            .annotate(
                runnable=Exact(
                    Cast(F("configured"), IntegerField())
                    * Cast(F("runnable"), IntegerField()),
                    1,
                )
            )
        )

    def get_signatures(self, job: Job) -> Generator[Signature, None, None]:
        from intel_owl import tasks

        for config in self:
            config: PythonConfig
            if not hasattr(config, "runnable"):
                raise RuntimeError(
                    "You have to call `annotate_runnable`"
                    " before being able to call `get_signature`"
                )
            # gen new task_id
            if not config.runnable:
                raise RuntimeWarning(
                    "You are trying to get the signature of a not runnable plugin"
                )

            task_id = str(uuid.uuid4())
            args = [
                job.pk,
                config.python_complete_path,
                config.pk,
                job.get_config_runtime_configuration(config),
                task_id,
            ]
            yield tasks.run_plugin.signature(
                args,
                {},
                queue=config.queue,
                soft_time_limit=config.soft_time_limit,
                task_id=task_id,
                immutable=True,
                MessageGroupId=str(task_id),
            )
