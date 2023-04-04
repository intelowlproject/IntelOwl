# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings
from django.core.validators import MinLengthValidator
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
    # contants
    DiscoverFromChoices = DiscoverFromChoices

    # fields
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="user_profile",
    )
    company_name = models.CharField(max_length=32, validators=[MinLengthValidator(3)])
    company_role = models.CharField(max_length=32, validators=[MinLengthValidator(3)])
    twitter_handle = models.CharField(
        max_length=16, default="", blank=True, validators=[MinLengthValidator(3)]
    )
    discover_from = models.CharField(
        max_length=32,
        choices=DiscoverFromChoices.choices,
        default=DiscoverFromChoices.OTHER,
    )

    # meta
    class Meta:
        verbose_name_plural = "User Profiles"
