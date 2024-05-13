# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings
from django.core.validators import (
    MaxValueValidator,
    MinLengthValidator,
    MinValueValidator,
)
from django.db import models

__all__ = [
    "UserProfile",
]

# constants


class DiscoverFromChoices(models.TextChoices):
    SEARCH_ENGINE = "search_engine", "Search Engine (Google, DuckDuckGo, etc.)"
    WAS_RECOMMENDED = "was_recommended", "Recommended by friend or colleague"
    SOCIAL_MEDIA = "social_media", "Social media"
    BLOG_OR_PUBLICATION = "blog_or_publication", "Blog or Publication"
    OTHER = "other", "Other"


# models


class UserProfile(models.Model):
    # constants
    DiscoverFromChoices = DiscoverFromChoices

    # fields
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    company_name = models.CharField(
        max_length=32, validators=[MinLengthValidator(3)], default="", blank=True
    )
    company_role = models.CharField(
        max_length=32, validators=[MinLengthValidator(3)], default="", blank=True
    )
    twitter_handle = models.CharField(
        max_length=16, default="", blank=True, validators=[MinLengthValidator(3)]
    )
    discover_from = models.CharField(
        max_length=32,
        choices=DiscoverFromChoices.choices,
        default=DiscoverFromChoices.OTHER,
    )
    task_priority = models.IntegerField(
        default=10, validators=[MaxValueValidator(10), MinValueValidator(1)]
    )
    is_robot = models.BooleanField(default=False)

    # meta
    class Meta:
        verbose_name_plural = "User Profiles"
