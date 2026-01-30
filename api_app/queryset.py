# flake8: noqa
"""
This module defines custom query sets for various models used in the IntelOwl project.
Each query set provides additional methods for filtering, annotating, and manipulating
query results specific to the needs of the IntelOwl application.
"""

import datetime
import json
import uuid
from typing import TYPE_CHECKING, Generator, Type

from django.conf import settings
from django.contrib.postgres.expressions import ArraySubquery
from django.core.paginator import Paginator
from treebeard.mp_tree import MP_NodeQuerySet

if TYPE_CHECKING:
    from api_app.models import PythonConfig
    from api_app.serializers import AbstractBIInterface

import logging

from celery.canvas import Signature
from django.db import IntegrityError, models
from django.db.models import (
    BooleanField,
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

from api_app.choices import TLP, ParamTypes
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.user.models import User

logger = logging.getLogger(__name__)


class SendToBiQuerySet(models.QuerySet):
    """
    A custom queryset that provides methods for sending data to a Business Intelligence (BI) system.

    Methods:
    - send_to_elastic_as_bi: Sends the queryset's data to an Elasticsearch BI index.
    """

    @classmethod
    def _get_bi_serializer_class(cls) -> Type["AbstractBIInterface"]:
        """
        Abstract method to get the BI serializer class.
        Must be implemented in subclasses.
        """
        raise NotImplementedError()

    @staticmethod
    def _create_index_template():
        """
        Creates an index template in Elasticsearch for BI data.
        """
        with open(settings.CONFIG_ROOT / "elastic_search_mappings" / "intel_owl_bi.json") as f:
            body = json.load(f)
            body["index_patterns"] = [f"{settings.ELASTICSEARCH_BI_INDEX}-*"]
            settings.ELASTICSEARCH_BI_CLIENT.indices.put_template(
                name=settings.ELASTICSEARCH_BI_INDEX, body=body
            )
            logger.info(f"created template for Elastic named {settings.ELASTICSEARCH_BI_INDEX}")

    def send_to_elastic_as_bi(self, max_timeout: int = 60) -> bool:
        """
        Sends the queryset's data to an Elasticsearch BI index.

        Args:
            max_timeout (int): The maximum request timeout in seconds.

        Returns:
            bool: True if there were errors during the operation, False otherwise.
        """
        from elasticsearch.helpers import bulk

        logger.info("BI start")
        self._create_index_template()
        BULK_MAX_SIZE = 1000
        found_errors = False

        p = Paginator(self, BULK_MAX_SIZE)
        for i in p.page_range:
            page = p.get_page(i)
            objects = page.object_list
            serializer = self._get_bi_serializer_class()(instance=objects, many=True)
            objects_serialized = serializer.data
            _, errors = bulk(
                settings.ELASTICSEARCH_BI_CLIENT,
                objects_serialized,
                request_timeout=max_timeout,
            )
            if errors:
                logger.error(f"Errors on sending to elastic: {errors}. We are not marking objects as sent.")
                found_errors |= errors
            else:
                logger.info("BI sent")
                self.model.objects.filter(pk__in=objects.values_list("pk", flat=True)).update(sent_to_bi=True)
        return found_errors


class CleanOnCreateQuerySet(models.QuerySet):
    """
    A custom queryset that ensures objects are cleaned before being saved to the database.

    Methods:
    - create: Creates and saves an object, ensuring its `clean` method is called.
    - many_to_many_to_array: Annotates the queryset with an array of related objects' primary keys.
    """

    def create(self, **kwargs):
        """
        Creates and saves an object, ensuring its `clean` method is called.

        Args:
            **kwargs: The fields to set on the created object.

        Returns:
            The created object.
        """
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
        """
        Annotates the queryset with an array of related objects' primary keys.

        Args:
            field (str): The field name of the many-to-many relation.
            field_to_save (str, optional): The name of the annotated field. Defaults to None.

        Returns:
            The annotated queryset.
        """
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


class OrganizationPluginConfigurationQuerySet(models.QuerySet):
    """
    A custom queryset for filtering plugin configurations based on organization.

    Methods:
    - filter_for_config: Filters configurations based on content type and object ID.
    """

    def filter_for_config(self, config_class, config_pk: str):
        """
        Filters configurations based on content type and object ID.

        Args:
            config_class: The class of the configuration.
            config_pk (str): The primary key of the configuration object.

        Returns:
            The filtered queryset.
        """
        return self.filter(content_type=config_class.get_content_type(), object_id=config_pk)


class AbstractConfigQuerySet(CleanOnCreateQuerySet):
    """
    A custom queryset for filtering and annotating configuration objects.

    Methods:
    - alias_disabled_in_organization: Annotates the queryset with a boolean indicating if the configuration is disabled in the organization.
    - annotate_runnable: Annotates the queryset with a boolean indicating if the configuration is runnable by a user.
    """

    def alias_disabled_in_organization(self, organization):
        """
        Annotates the queryset with a boolean indicating if the configuration is disabled in the organization.

        Args:
            organization: The organization to check.

        Returns:
            The annotated queryset.
        """
        from api_app.models import OrganizationPluginConfiguration

        opc = OrganizationPluginConfiguration.objects.filter(organization=organization)

        return self.alias(
            disabled_in_organization=Exists(
                opc.filter_for_config(config_class=self.model, config_pk=OuterRef("pk")).filter(disabled=True)
            )
        )

    def annotate_runnable(self, user: User = None) -> QuerySet:
        """
        Annotates the queryset with a boolean indicating if the configuration is runnable by a user.

        Args:
            user (User, optional): The user to check. Defaults to None.

        Returns:
            The annotated queryset.
        """
        # the plugin is runnable IF
        # - it is not disabled
        # - the user is not inside an organization that have disabled the plugin
        qs = self.filter(
            pk=OuterRef("pk"),
        ).exclude(disabled=True)
        if user and user.has_membership():
            qs = qs.alias_disabled_in_organization(user.membership.organization)
            qs = qs.exclude(disabled_in_organization=True)
        return self.annotate(runnable=Exists(qs))


class JobQuerySet(MP_NodeQuerySet, CleanOnCreateQuerySet, SendToBiQuerySet):
    """
    A custom queryset for managing Job objects, providing methods for job creation, deletion, and filtering.

    Methods:
    - create: Creates a job, setting it as a child of the specified parent if provided.
    - delete: Deletes jobs, ensuring the correct method is called.
    - filter_completed: Filters jobs that have completed.
    - visible_for_user: Filters jobs visible to a specific user based on TLP and user organization.
    - _annotate_importance_date: Annotates jobs with a weight based on the completion date.
    - _annotate_importance_user: Annotates jobs with a weight based on the user and their organization.
    - annotate_importance: Annotates jobs with an overall importance score.
    - running: Filters jobs that are currently running.
    """

    def create(self, parent=None, **kwargs):
        """
        Creates a job, setting it as a child of the specified parent if provided.

        Args:
            parent (optional): The parent job, if any.
            **kwargs: The fields to set on the created job.

        Returns:
            The created job.
        """
        if parent:
            return parent.add_child(**kwargs)
        # try multiple times hoping to for no race conditions
        total_attempt_number = 5
        for attempt in range(0, total_attempt_number):
            try:
                return self.model.add_root(**kwargs)
            except IntegrityError:
                logger.warning(f"Found race condition for {kwargs['name']}. Trying again to calculate path.")
                if attempt == total_attempt_number - 1:
                    raise

    def delete(self, *args, **kwargs):
        """
        Deletes jobs, ensuring the correct method is called.

        Args:
            *args: Additional arguments.
            **kwargs: Additional keyword arguments.
        """
        # just to be sure to call the correct method
        return MP_NodeQuerySet.delete(self, *args, **kwargs)

    @classmethod
    def _get_bi_serializer_class(cls):
        """
        Gets the BI serializer class for Job objects.

        Returns:
            The JobBISerializer class.
        """
        from api_app.serializers.job import JobBISerializer

        return JobBISerializer

    def filter_completed(self):
        """
        Filters jobs that have completed.

        Returns:
            The filtered queryset.
        """
        return self.filter(status__in=self.model.STATUSES.final_statuses())

    def visible_for_user(self, user: User) -> "JobQuerySet":
        """
        User has access to:
        - jobs with TLP = CLEAR or GREEN
        - jobs with TLP = AMBER or RED and
        - jobs made by ingestors if the user is an admin
        created by a member of their organization.
        """
        if user.has_membership():
            user_query = Q(user=user) | Q(user__membership__organization_id=user.membership.organization_id)
        else:
            user_query = Q(user=user)
        if user.is_superuser:
            user_query |= Q(user__ingestors__isnull=False)

        query = Q(tlp__in=[TLP.CLEAR, TLP.GREEN]) | (Q(tlp__in=[TLP.AMBER, TLP.RED]) & user_query)
        return self.filter(query)

    def _annotate_importance_date(self) -> "JobQuerySet":
        """
        Annotates jobs with a weight based on the completion date.

        Returns:
            The annotated queryset.
        """
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
        """
        Annotates jobs with a weight based on the user and their organization.

        Args:
            user (User): The user to check.

        Returns:
            The annotated queryset.
        """
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
        """
        Annotates jobs with an overall importance score.

        Args:
            user (User, optional): The user to check. Defaults to None.

        Returns:
            The annotated queryset.
        """
        return (
            self._annotate_importance_date()
            ._annotate_importance_user(user)
            .annotate(importance=F("date_weight") + F("user_weight"))
        )

    def running(self, check_pending: bool = False, minutes_ago: int = 25) -> "JobQuerySet":
        """
        Filters jobs that are currently running.

        Returns:
            The filtered queryset.
        """
        qs = self.exclude(status__in=[status.value for status in self.model.STATUSES.final_statuses()])
        if not check_pending:
            qs = qs.exclude(status=self.model.STATUSES.PENDING.value)
        difference = now() - datetime.timedelta(minutes=minutes_ago)
        return qs.filter(received_request_time__lte=difference)


class ParameterQuerySet(CleanOnCreateQuerySet):
    """
    Custom queryset for managing parameters, providing methods for filtering and annotating based on user configuration.

    Methods:
    - annotate_configured: Annotates parameters indicating if they are configured for a specific user.
    - _alias_owner_value_for_user: Aliases the owner value for a user.
    - _alias_org_value_for_user: Aliases the organization value for a user.
    - _alias_default_value: Aliases the default value for a parameter.
    - _alias_runtime_config: Aliases runtime configuration values.
    - _alias_for_test: Aliases values for testing environments.
    - annotate_value_for_user: Annotates the final value for a user, considering runtime, owner, organization, default, and test values.
    """

    def annotate_configured(self, config: "PythonConfig", user: User = None) -> "ParameterQuerySet":
        """
        Annotates parameters indicating if they are configured for a specific user.

        Args:
            config (PythonConfig): The configuration to check against.
            user (User, optional): The user to check. Defaults to None.

        Returns:
            ParameterQuerySet: The annotated queryset.
        """
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

    def _alias_owner_value_for_user(self, config: "PythonConfig", user: User = None) -> "ParameterQuerySet":
        """
        Aliases the owner value for a user.

        Args:
            config (PythonConfig): The configuration to check against.
            user (User, optional): The user to check. Defaults to None.

        Returns:
            ParameterQuerySet: The aliased queryset.
        """
        from api_app.models import PluginConfig

        return self.alias(
            owner_value=Subquery(
                PluginConfig.objects.filter(
                    parameter__pk=OuterRef("pk"),
                    **{config.snake_case_name: config.pk},
                    for_organization=False,
                )
                .visible_for_user_owned(user)
                .values("value")[:1],
            )
        )

    def _alias_org_value_for_user(self, config: "PythonConfig", user: User = None) -> "ParameterQuerySet":
        """
        Aliases the organization value for a user.

        Args:
            config (PythonConfig): The configuration to check against.
            user (User, optional): The user to check. Defaults to None.

        Returns:
            ParameterQuerySet: The aliased queryset.
        """
        from api_app.models import PluginConfig

        return self.alias(
            org_value=(
                Subquery(
                    PluginConfig.objects.filter(
                        parameter__pk=OuterRef("pk"),
                        **{config.snake_case_name: config.pk},
                    )
                    .visible_for_user_by_org(user)
                    .values("value")[:1],
                )
                if user and user.has_membership()
                else Value(None, output_field=JSONField())
            ),
        )

    def _alias_default_value(self, config: "PythonConfig") -> "ParameterQuerySet":
        """
        Aliases the default value for a parameter.

        Args:
            config (PythonConfig): The configuration to check against.

        Returns:
            ParameterQuerySet: The aliased queryset.
        """
        from api_app.models import PluginConfig

        return self.alias(
            default_value=Subquery(
                PluginConfig.objects.filter(
                    parameter__pk=OuterRef("pk"), **{config.snake_case_name: config.pk}
                )
                .default_values()
                .values("value")[:1],
            )
        )

    def _alias_runtime_config(self, runtime_config=None):
        """
        Aliases runtime configuration values.

        Args:
            runtime_config (dict, optional): The runtime configuration. Defaults to None.

        Returns:
            ParameterQuerySet: The aliased queryset.
        """
        if not runtime_config:
            runtime_config = {}
        # we are creating conditions for when runtime config should be used
        whens = [
            When(name=para, then=Value(value, output_field=JSONField()))
            for para, value in runtime_config.items()
        ]
        return self.annotate(runtime_value=Case(*whens, default=None, output_field=JSONField()))

    def _alias_for_test(self):
        """
        Aliases values for testing environments.

        Returns:
            ParameterQuerySet: The aliased queryset.
        """
        if not settings.STAGE_CI and not settings.MOCK_CONNECTIONS:
            return self.alias(
                test_value=Value(
                    None,
                )
            )
        return self.alias(
            test_value=Case(
                When(
                    name__icontains="url",
                    then=Value("https://intelowl.com", output_field=JSONField()),
                ),
                When(
                    name="pdns_credentials",
                    then=Value("user|pwd", output_field=JSONField()),
                ),
                When(name__contains="test", then=Value(None, output_field=JSONField())),
                When(type=ParamTypes.INT.value, then=Value(10, output_field=JSONField())),
                When(
                    type=ParamTypes.LIST.value,
                    then=Value(["test"], output_field=JSONField()),
                ),
                default=Value("test", output_field=JSONField()),
                output_field=JSONField(),
            )
        )

    def annotate_value_for_user(
        self, config: "PythonConfig", user: User = None, runtime_config=None
    ) -> "ParameterQuerySet":
        """
        Annotates the final value for a user, considering runtime, owner, organization, default, and test values.

        Args:
            config (PythonConfig): The configuration to check against.
            user (User, optional): The user to check. Defaults to None.
            runtime_config (dict, optional): The runtime configuration. Defaults to None.

        Returns:
            ParameterQuerySet: The annotated queryset.
        """
        return (
            self.prefetch_related("values")
            ._alias_owner_value_for_user(config, user)
            ._alias_org_value_for_user(config, user)
            ._alias_default_value(config)
            ._alias_runtime_config(runtime_config)
            ._alias_for_test()
            # importance order
            .annotate(
                # 1. runtime
                # 2. owner
                # 3. organization
                # 4. default value
                # 5. (if TEST environment) test value
                # 5. (if NOT TEST environment) None
                value=Case(
                    When(
                        runtime_value__isnull=False,
                        then=Cast(F("runtime_value"), output_field=JSONField()),
                    ),
                    When(
                        owner_value__isnull=False,
                        then=Cast(F("owner_value"), output_field=JSONField()),
                    ),
                    When(
                        org_value__isnull=False,
                        then=Cast(F("org_value"), output_field=JSONField()),
                    ),
                    When(
                        default_value__isnull=False,
                        then=Cast(F("default_value"), output_field=JSONField()),
                    ),
                    default=Cast(F("test_value"), output_field=JSONField()),
                    output_field=JSONField(),
                ),
                is_from_org=Case(
                    When(
                        runtime_value__isnull=True,
                        owner_value__isnull=True,
                        org_value__isnull=False,
                        then=Value(True),
                    ),
                    default=Value(False),
                    output_field=BooleanField(),
                ),
            )
        )


class AbstractReportQuerySet(SendToBiQuerySet):
    """
    Custom queryset for managing reports, providing methods for filtering based on status.

    Methods:
    - filter_completed: Filters reports that are completed.
    - filter_retryable: Filters reports that are retryable.
    - get_configurations: Retrieves configurations associated with the reports.
    """

    def filter_completed(self):
        """
        Filters reports that are completed.

        Returns:
            AbstractReportQuerySet: The filtered queryset.
        """
        return self.filter(status__in=self.model.STATUSES.final_statuses())

    def filter_retryable(self):
        """
        Filters reports that are retryable.

        Returns:
            AbstractReportQuerySet: The filtered queryset.
        """
        return self.filter(
            status__in=[
                self.model.STATUSES.FAILED.value,
                self.model.STATUSES.PENDING.value,
            ]
        )

    def get_configurations(self) -> AbstractConfigQuerySet:
        """
        Retrieves configurations associated with the reports.

        Returns:
            AbstractConfigQuerySet: The queryset of configurations.
        """
        return self.model.config.field.related_model.objects.filter(pk__in=self.values("config_id"))


class ModelWithOwnershipQuerySet:
    """
    Custom queryset for managing models with ownership, providing methods for filtering based on ownership.

    Methods:
    - default_values: Retrieves default values.
    - visible_for_user_by_org: Filters values visible to a user by their organization.
    - visible_for_user_owned: Filters values owned by a user.
    - visible_for_user: Filters values visible to a user.
    """

    def default_values(self):
        """
        Retrieves default values.

        Returns:
            ModelWithOwnershipQuerySet: The filtered queryset.
        """
        return self.filter(owner__isnull=True)

    def visible_for_user_by_org(self, user: User):
        """
        Filters values visible to a user by their organization.

        Args:
            user (User): The user to check.

        Returns:
            ModelWithOwnershipQuerySet: The filtered queryset.
        """
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
        """
        Filters values owned by a user.

        Args:
            user (User): The user to check.

        Returns:
            ModelWithOwnershipQuerySet: The filtered queryset.
        """
        return self.filter(owner=user)

    def visible_for_user(self, user: User = None) -> "PluginConfigQuerySet":
        """
        Filters values visible to a user.

        Args:
            user (User, optional): The user to check. Defaults to None.

        Returns:
            PluginConfigQuerySet: The filtered queryset.
        """
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
    """
    Custom queryset for PluginConfig model, extending CleanOnCreateQuerySet and ModelWithOwnershipQuerySet.

    Inherits:
    - CleanOnCreateQuerySet: Provides clean method for objects on creation.
    - ModelWithOwnershipQuerySet: Provides methods for filtering based on ownership.
    """

    ...


class PythonConfigQuerySet(AbstractConfigQuerySet):
    """
    Custom queryset for PythonConfig model, providing methods for annotating configurations.

    Methods:
    - annotate_configured: Annotates configurations indicating if they are fully configured.
    - annotate_runnable: Annotates configurations indicating if they are runnable.
    - get_signatures: Generates task signatures for each configuration.
    """

    def annotate_configured(self, user: User = None) -> "PythonConfigQuerySet":
        """
        Annotates configurations indicating if they are fully configured.

        Args:
            user (User, optional): The user to check. Defaults to None.

        Returns:
            PythonConfigQuerySet: The annotated queryset.
        """
        # a Python plugin is configured only if every required parameter is configured
        from api_app.models import Parameter, PluginConfig

        return (
            # we retrieve the number or required parameters
            self.alias(
                required_params=Coalesce(
                    Subquery(
                        Parameter.objects.filter(python_module=OuterRef("python_module"), required=True)
                        # count them
                        .annotate(count=Func(F("pk"), function="Count"))
                        .values("count"),
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
                                    **{self.model.snake_case_name: OuterRef(OuterRef("pk"))},
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
            .annotate(configured=Exact(F("required_params") - F("required_configured_params"), 0))
        )

    def annotate_runnable(self, user: User = None) -> "PythonConfigQuerySet":
        """
        Annotates configurations indicating if they are runnable.

        Args:
            user (User, optional): The user to check. Defaults to None.

        Returns:
            PythonConfigQuerySet: The annotated queryset.
        """
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
                    Cast(F("configured"), IntegerField()) * Cast(F("runnable"), IntegerField()),
                    1,
                )
            )
        )

    def get_signatures(self, job) -> Generator[Signature, None, None]:
        """
        Generates task signatures for each configuration.

        Args:
            job (Job): The job instance.

        Yields:
            Generator[Signature, None, None]: A generator of task signatures.
        """
        from api_app.models import AbstractReport, Job, PythonConfig
        from intel_owl import tasks

        job: Job
        for config in self:
            config: PythonConfig
            if not hasattr(config, "runnable"):
                raise RuntimeError(
                    "You have to call `annotate_runnable` before being able to call `get_signature`"
                )
            # gen new task_id
            if not config.runnable:
                raise RuntimeWarning("You are trying to get the signature of a not runnable plugin")

            task_id = str(uuid.uuid4())
            config.generate_empty_report(job, task_id, AbstractReport.STATUSES.PENDING.value)
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
                priority=job.priority,
            )


class CommentQuerySet(QuerySet):
    def visible_for_user(self, user):
        from api_app.analyzables_manager.models import Analyzable

        analyzables = Analyzable.objects.visible_for_user(user)
        qs = self.filter(analyzable__in=analyzables.values_list("pk", flat=True))
        if user.has_membership():
            qs = qs.filter(user__membership__organization__pk=user.membership.organization.pk)
        else:
            qs = qs.filter(user=user)
        return qs
