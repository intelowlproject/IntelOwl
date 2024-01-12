import datetime
import json
import logging
import uuid
from typing import TYPE_CHECKING, Generator, Type

from django.conf import settings
from django.contrib.postgres.expressions import ArraySubquery
from django.core.paginator import Paginator

if TYPE_CHECKING:
    from api_app.models import PythonConfig
    from api_app.serializers import AbstractBIInterface

from celery.canvas import Signature
from django.db import models
from django.db.models import (
    Case,
    Exists,
    F,
    Func,
    IntegerField,
    JSONField,
    OuterRef,
    Q,
    QuerySet,
    Subquery,
    Value,
    When,
)
from django.db.models.functions import Cast, Coalesce
from django.db.models.lookups import Exact
from django.utils.timezone import now

from api_app.choices import TLP
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.user.models import User


class SendToBiQuerySet(models.QuerySet):
    @classmethod
    def _get_bi_serializer_class(cls) -> Type["AbstractBIInterface"]:
        raise NotImplementedError()

    @staticmethod
    def _create_index_template():
        if not settings.ELASTICSEARCH_CLIENT.indices.exists_template(
            name=settings.ELASTICSEARCH_BI_INDEX
        ):
            with open(
                settings.CONFIG_ROOT / "elastic_search_mappings" / "intel_owl_bi.json"
            ) as f:
                body = json.load(f)
                body["index_patterns"] = [f"{settings.ELASTICSEARCH_BI_INDEX}-*"]
                settings.ELASTICSEARCH_CLIENT.indices.put_template(
                    name=settings.ELASTICSEARCH_BI_INDEX, body=body
                )

    def send_to_elastic_as_bi(self, max_timeout: int = 60) -> bool:
        from elasticsearch.helpers import bulk

        BULK_MAX_SIZE = 1000
        found_errors = False

        p = Paginator(self, BULK_MAX_SIZE)
        for i in p.page_range:
            page = p.get_page(i)
            objects = page.object_list
            serializer = self._get_bi_serializer_class()(instance=objects, many=True)
            objects_serialized = serializer.data
            _, errors = bulk(
                settings.ELASTICSEARCH_CLIENT,
                objects_serialized,
                request_timeout=max_timeout,
            )
            if errors:
                logging.error(
                    f"Errors on sending to elastic: {errors}."
                    " We are not marking objects as sent."
                )
                found_errors |= errors
            else:
                logging.info("BI sent")
                self.model.objects.filter(
                    pk__in=objects.values_list("pk", flat=True)
                ).update(sent_to_bi=True)
        self._create_index_template()
        return found_errors


class CleanOnCreateQuerySet(models.QuerySet):
    def create(self, **kwargs):
        obj = self.model(**kwargs)
        obj: models.Model
        # we are forcing the clean method call.
        # django rest framework DOES NOT do that by default,
        # and I want to be sure that it is actually caled
        obj.clean()
        self._for_write = True
        obj.save(force_insert=True, using=self.db)
        return obj

    def many_to_many_to_array(self, field: str, field_to_save: str = None):
        if not field_to_save:
            field_to_save = f"{field}_array"
        return self.annotate(
            **{
                field_to_save: ArraySubquery(
                    self.model.objects.filter(pk=OuterRef("pk")).values(f"{field}__pk"),
                    default=Value([]),
                )
            }
        )


class AbstractConfigQuerySet(CleanOnCreateQuerySet):
    def annotate_runnable(self, user: User = None) -> QuerySet:
        # the plugin is runnable IF
        # - it is not disabled
        # - the user is not inside an organization that have disabled the plugin
        qs = self.filter(
            pk=OuterRef("pk"),
        ).exclude(disabled=True)

        if user and user.has_membership():
            qs = qs.exclude(
                disabled_in_organizations=user.membership.organization,
            )
        return self.annotate(runnable=Exists(qs))


class JobQuerySet(CleanOnCreateQuerySet, SendToBiQuerySet):
    @classmethod
    def _get_bi_serializer_class(cls):
        from api_app.serializers import JobBISerializer

        return JobBISerializer

    def visible_for_user(self, user: User) -> "JobQuerySet":
        """
        User has access to:
        - jobs with TLP = CLEAR or GREEN
        - jobs with TLP = AMBER or RED and
        - jobs made by ingestors if the user is an admin
        created by a member of their organization.
        """
        if user.has_membership():
            user_query = Q(user=user) | Q(
                user__membership__organization_id=user.membership.organization_id
            )
        else:
            user_query = Q(user=user)
        if user.is_superuser:
            user_query |= Q(user__ingestors__isnull=False)

        query = Q(tlp__in=[TLP.CLEAR, TLP.GREEN]) | (
            Q(tlp__in=[TLP.AMBER, TLP.RED]) & user_query
        )
        return self.filter(query)

    def _annotate_importance_date(self) -> "JobQuerySet":
        # the scans in the last day get a 3x
        # the scans in the last week get a 2x

        return self.annotate(
            date_weight=Case(
                When(
                    finished_analysis_time__gte=now() - datetime.timedelta(hours=24),
                    then=Value(3),
                ),
                When(
                    finished_analysis_time__gte=now() - datetime.timedelta(days=7),
                    then=Value(2),
                ),
                default=Value(0),
            ),
        )

    def _annotate_importance_user(self, user: User) -> "JobQuerySet":
        # the scans from the user get a 3x
        # the scans from the same org get a 2x
        user_case = Case(When(user__pk=user.pk, then=Value(3)), default=Value(0))
        if user.has_membership():
            user_case.cases.append(
                When(
                    user__membership__organization__pk=user.membership.organization.pk,
                    then=Value(2),
                )
            )

        return self.annotate(user_weight=user_case)

    def annotate_importance(self, user: User) -> QuerySet:
        return (
            self._annotate_importance_date()
            ._annotate_importance_user(user)
            .annotate(importance=F("date_weight") + F("user_weight"))
        )


class ParameterQuerySet(CleanOnCreateQuerySet):
    def annotate_configured(
        self, config: "PythonConfig", user: User = None
    ) -> "ParameterQuerySet":
        from api_app.models import PluginConfig

        # A parameter it is configured for a user if
        # there is a PluginConfig that is visible for the user
        # If the user is None, we only retrieve default parameters
        return self.annotate(
            configured=Exists(
                PluginConfig.objects.filter(
                    parameter=OuterRef("pk"), **{config.snake_case_name: config.pk}
                ).visible_for_user(user)
            )
        )

    def _alias_owner_value_for_user(
        self, config: "PythonConfig", user: User = None
    ) -> "ParameterQuerySet":
        from api_app.models import PluginConfig

        return self.alias(
            owner_value=Subquery(
                PluginConfig.objects.filter(
                    parameter__pk=OuterRef("pk"), **{config.snake_case_name: config.pk}
                )
                .visible_for_user_owned(user)
                .values("value")[:1]
            )
        )

    def _alias_org_value_for_user(
        self, config: "PythonConfig", user: User = None
    ) -> "ParameterQuerySet":
        from api_app.models import PluginConfig

        return self.alias(
            org_value=Subquery(
                PluginConfig.objects.filter(
                    parameter__pk=OuterRef("pk"), **{config.snake_case_name: config.pk}
                )
                .visible_for_user_by_org(user)
                .values("value")[:1]
            )
            if user and user.has_membership()
            else Value(None, output_field=JSONField()),
        )

    def _alias_default_value(self, config: "PythonConfig") -> "ParameterQuerySet":
        from api_app.models import PluginConfig

        return self.alias(
            default_value=Subquery(
                PluginConfig.objects.filter(
                    parameter__pk=OuterRef("pk"), **{config.snake_case_name: config.pk}
                )
                .default_values()
                .values("value")[:1]
            )
        )

    def annotate_value_for_user(
        self, config: "PythonConfig", user: User = None
    ) -> "ParameterQuerySet":
        return (
            self.prefetch_related("values")
            ._alias_owner_value_for_user(config, user)
            ._alias_org_value_for_user(config, user)
            ._alias_default_value(config)
            # importance order
            .annotate(
                value=Case(
                    When(owner_value__isnull=False, then=F("owner_value")),
                    When(org_value__isnull=False, then=F("org_value")),
                    default=F("default_value"),
                ),
                is_from_org=Case(
                    When(
                        org_value__isnull=True,
                        owner_value__isnull=False,
                        then=Value(True),
                    ),
                    default=Value(False),
                ),
            )
        )


class AbstractReportQuerySet(SendToBiQuerySet):
    ...


class ModelWithOwnershipQuerySet:
    def default_values(self):
        return self.filter(owner__isnull=True)

    def visible_for_user_by_org(self, user: User):
        try:
            membership = Membership.objects.get(user=user)
        except Membership.DoesNotExist:
            return self.none()
        else:
            # If you are member of an organization you should see the configs.
            return self.filter(
                for_organization=True,
                owner__membership__organization=membership.organization,
            )

    def visible_for_user_owned(self, user: User):
        return self.filter(owner=user)

    def visible_for_user(self, user: User = None) -> "PluginConfigQuerySet":
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
                # If you are member of an organization you should see the configs.
                return self.filter(
                    Q(
                        for_organization=True,
                        owner__membership__organization=membership.organization,
                    )
                    | Q(owner=user)
                    | Q(owner__isnull=True)
                )
        else:
            return self.default_values()


class PluginConfigQuerySet(CleanOnCreateQuerySet, ModelWithOwnershipQuerySet):
    ...


class PythonConfigQuerySet(AbstractConfigQuerySet):
    def annotate_configured(self, user: User = None) -> "PythonConfigQuerySet":
        # a Python plugin is configured only if every required parameter is configured
        from api_app.models import Parameter, PluginConfig

        return (
            # we retrieve the number or required parameters
            self.alias(
                required_params=Coalesce(
                    Subquery(
                        Parameter.objects.filter(
                            python_module=OuterRef("python_module"), required=True
                        )
                        # count them
                        .annotate(count=Func(F("pk"), function="Count")).values(
                            "count"
                        ),
                        output_field=IntegerField(),
                    ),
                    0,
                )
            )
            # how many of them are configured
            .alias(
                # just to be sure that if the query fails, we return an integered
                required_configured_params=Coalesce(
                    Subquery(
                        # we count how many parameters have a valid value
                        # considering the values that the user has access to
                        Parameter.objects.filter(
                            pk__in=Subquery(
                                # we get all values that the user can see
                                PluginConfig.objects.filter(
                                    **{
                                        self.model.snake_case_name: OuterRef(
                                            OuterRef("pk")
                                        )
                                    },
                                    parameter__required=True,
                                )
                                .visible_for_user(user)
                                .values("parameter__pk")
                            )
                        )
                        .annotate(count=Func(F("pk"), function="Count"))
                        .values("count"),
                        output_field=IntegerField(),
                    ),
                    0,
                )
            )
            # and we save the difference
            .annotate(
                configured=Exact(
                    F("required_params") - F("required_configured_params"), 0
                )
            )
        )

    def annotate_runnable(self, user: User = None) -> "PythonConfigQuerySet":
        # we are excluding the plugins that has failed the health_check
        qs = (
            self.exclude(health_check_status=False)
            # we save the `configured` attribute in the queryset
            .annotate_configured(user)
        )
        return (
            # this super call parameters are required
            super(PythonConfigQuerySet, qs)
            # we set the parent `runnable` attribute
            .annotate_runnable(user)
            # and we do the logic AND between the two fields
            .annotate(
                runnable=Exact(
                    # I have no idea how to do the compare
                    # of two boolean field in a subquery.
                    # this is the same as runnable =`configured` AND `runnable`
                    Cast(F("configured"), IntegerField())
                    * Cast(F("runnable"), IntegerField()),
                    1,
                )
            )
        )

    def get_signatures(self, job) -> Generator[Signature, None, None]:
        from api_app.models import AbstractReport, Job, PythonConfig
        from intel_owl import tasks

        job: Job
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
            config.generate_empty_report(
                job, task_id, AbstractReport.Status.PENDING.value
            )
            args = [
                job.pk,
                config.python_module_id,
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


class IngestorQuerySet(PythonConfigQuerySet):
    def annotate_runnable(self, user: User = None) -> "PythonConfigQuerySet":
        # the plugin is runnable IF
        # - it is not disabled
        qs = self.filter(
            pk=OuterRef("pk"),
        ).exclude(disabled=True)

        return self.annotate(runnable=Exists(qs))
