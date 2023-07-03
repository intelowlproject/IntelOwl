from django.db import models
from django.db.models import Q

from certego_saas.apps.user.models import User


class CleanOnCreateQuerySet(models.QuerySet):
    def create(self, **kwargs):
        obj = self.model(**kwargs)
        obj: models.Model
        obj.full_clean()
        self._for_write = True
        obj.save(force_insert=True, using=self.db)
        return obj


class AbstractConfigQuerySet(CleanOnCreateQuerySet):
    def runnable(self, user: User = None):

        if user and user.has_membership():
            organization_query = Q(
                disabled_in_organization=user.membership.organization
            )
        else:
            organization_query = Q()

        return self.filter(disabled=True).exclude(organization_query)
