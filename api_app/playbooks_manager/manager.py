from django.db import models
from django.db.models import Subquery, Func, OuterRef, F, Value

from api_app.models import Job
from certego_saas.apps.user.models import User


class PlaybookConfigManager(models.Manager):

    def __subquery_user(self, user: User) -> Subquery:
        return Subquery(
            Job.objects.filter(user__pk=user.pk, playbook_to_execute=OuterRef("pk"))
            .annotate(count=Func(F("pk"), function="Count"))
            .values("count")
        )

    def __subquery_org(self, user: User) -> Subquery:
        if user.has_membership():
            return Subquery(
                Job.objects.filter(
                    user__membership__organization__pk=user.membership.organization.pk,
                    playbook_to_execute=OuterRef("pk"),
                )
                .exclude(user__pk=user.pk)
                .annotate(count=Func(F("pk"), function="Count"))
                .values("count")
            )
        return Value(0)

    def __subquery_other(self, user:User) -> Subquery:
        if user.has_membership():
            return Subquery(
                Job.objects.filter(playbook_to_execute=OuterRef("pk"))
                .exclude(
                    user__membership__organization__pk=user.membership.organization.pk
                )
                .annotate(count=Func(F("pk"), function="Count"))
                .values("count")
            )
        return Subquery(
                Job.objects.filter(playbook_to_execute=OuterRef("pk"))
                .exclude(user__pk=user.pk)
                .annotate(count=Func(F("pk"), function="Count"))
                .values("count")
            )

    def ordered_for_user(self, user: User):
        USER_WEIGHT_MULTIPLICATIVE = 3
        ORG_WEIGHT_MULTIPLICATIVE = 2
        OTHER_WEIGHT_MULTIPLICATIVE = 1

        return (
            self.annotate(
                user_weight=self.__subquery_user(user),
                org_weight=self.__subquery_org(user),
                other_weight=self.__subquery_other(user),
            )
            .annotate(
                weight=F("user_weight") * USER_WEIGHT_MULTIPLICATIVE
                       + F("org_weight") * ORG_WEIGHT_MULTIPLICATIVE
                       + F("other_weight") * OTHER_WEIGHT_MULTIPLICATIVE
            )
            .order_by("-weight", "-name")
        )
