import datetime
from typing import Union

from django.db.models import F, Func, OuterRef, QuerySet, Subquery, Value
from django.utils.timezone import now

from api_app.models import Job
from api_app.queryset import AbstractConfigQuerySet, ModelWithOwnershipQuerySet
from certego_saas.apps.user.models import User


class PlaybookConfigQuerySet(AbstractConfigQuerySet, ModelWithOwnershipQuerySet):
    @staticmethod
    def _subquery_weight_user(user: User) -> Subquery:
        return Subquery(
            Job.objects.prefetch_related("user")
            .filter(
                user__pk=user.pk,
                playbook_to_execute=OuterRef("pk"),
                finished_analysis_time__gte=now() - datetime.timedelta(days=30),
            )
            .annotate(count=Func(F("pk"), function="Count"))
            .values("count")
        )

    @staticmethod
    def _subquery_weight_org(user: User) -> Union[Subquery, Value]:
        if user.has_membership():
            return Subquery(
                Job.objects.prefetch_related("user")
                .filter(
                    user__membership__organization__pk=user.membership.organization.pk,
                    playbook_to_execute=OuterRef("pk"),
                    finished_analysis_time__gte=now() - datetime.timedelta(days=30),
                )
                .exclude(user__pk=user.pk)
                .annotate(count=Func(F("pk"), function="Count"))
                .values("count")
            )
        return Value(0)

    @staticmethod
    def _subquery_weight_other(user: User) -> Subquery:
        if user.has_membership():
            return Subquery(
                Job.objects.filter(
                    playbook_to_execute=OuterRef("pk"),
                    finished_analysis_time__gte=now() - datetime.timedelta(days=30),
                )
                .exclude(
                    user__membership__organization__pk=user.membership.organization.pk
                )
                .annotate(count=Func(F("pk"), function="Count"))
                .values("count")
            )
        return Subquery(
            Job.objects.prefetch_related("user")
            .filter(playbook_to_execute=OuterRef("pk"))
            .exclude(user__pk=user.pk)
            .annotate(count=Func(F("pk"), function="Count"))
            .values("count")
        )

    def ordered_for_user(self, user: User) -> QuerySet:
        USER_WEIGHT_MULTIPLICATIVE = 3
        ORG_WEIGHT_MULTIPLICATIVE = 2
        OTHER_WEIGHT_MULTIPLICATIVE = 1

        return (
            self.prefetch_related("executed_in_jobs")
            .annotate(
                user_weight=self._subquery_weight_user(user),
                org_weight=self._subquery_weight_org(user),
                other_weight=self._subquery_weight_other(user),
            )
            .annotate(
                weight=(F("user_weight") * USER_WEIGHT_MULTIPLICATIVE)
                + (F("org_weight") * ORG_WEIGHT_MULTIPLICATIVE)
                + (F("other_weight") * OTHER_WEIGHT_MULTIPLICATIVE)
            )
            .order_by("-weight", "name")
        )
