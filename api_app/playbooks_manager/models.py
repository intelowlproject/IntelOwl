# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models
from django.conf import settings
from certego_saas.apps.organization.organization import Organization


class CachedPlaybook(models.Model):
    name = models.CharField(max_length=225, primary_key=True)
    # Required fields
    description = models.CharField(max_length=225, default="", blank=True)
    analyzers = models.JSONField(default=dict)
    connectors = models.JSONField(default=dict)

    # Optional Fields
    supports = models.JSONField(default=list)
    disabled = models.BooleanField(default=False)

    # For permissions
    # if null, organizations would be used for reference.
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,  # for backwards compatibility
        blank=True,
        related_name="cachedplaybook_owner"
    )

    # if null, organization will not be used for
    # a reference
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        blank=True,
        null=True, # for backwards compatibility
        related_name="cachedplaybook_organization"
    )

    # if both owner and organization would be null, 
    # it would be assumed that it is meant to be kept
    # open to all.
