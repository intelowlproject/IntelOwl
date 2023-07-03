from django.db import models
from django.db.models import Q, QuerySet

from api_app.choices import TLP
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
    def runnable(self, user: User = None) -> QuerySet:

        if user and user.has_membership():
            organization_query = Q(
                disabled_in_organization=user.membership.organization
            )
        else:
            organization_query = Q()

        return self.filter(disabled=True).exclude(organization_query)


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
