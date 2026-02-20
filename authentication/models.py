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
    """
    Choices for how the user discovered the platform.

    Attributes:
        SEARCH_ENGINE (str): Discovered via search engine.
        WAS_RECOMMENDED (str): Recommended by a friend or colleague.
        SOCIAL_MEDIA (str): Discovered via social media.
        BLOG_OR_PUBLICATION (str): Discovered via a blog or publication.
        OTHER (str): Discovered through other means.
    """

    SEARCH_ENGINE = "search_engine", "Search Engine (Google, DuckDuckGo, etc.)"
    WAS_RECOMMENDED = "was_recommended", "Recommended by friend or colleague"
    SOCIAL_MEDIA = "social_media", "Social media"
    BLOG_OR_PUBLICATION = "blog_or_publication", "Blog or Publication"
    OTHER = "other", "Other"


class UserProfile(models.Model):
    """
    Model representing a user profile.

    Attributes:
        user (OneToOneField): One-to-one relationship with the user model.
        company_name (CharField): Name of the company the user is associated with.
        company_role (CharField): Role of the user in the company.
        twitter_handle (CharField): User's Twitter handle.
        discover_from (CharField): How the user discovered the platform.
        task_priority (IntegerField): Priority of the user's tasks.
        is_robot (BooleanField): Indicates if the user is a robot.
    """

    # constants
    DiscoverFromChoices = DiscoverFromChoices

    # fields
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    company_name = models.CharField(max_length=32, validators=[MinLengthValidator(3)], default="", blank=True)
    company_role = models.CharField(max_length=32, validators=[MinLengthValidator(3)], default="", blank=True)
    twitter_handle = models.CharField(
        max_length=16, default="", blank=True, validators=[MinLengthValidator(3)]
    )
    discover_from = models.CharField(
        max_length=32,
        choices=DiscoverFromChoices.choices,
        default=DiscoverFromChoices.OTHER,
    )
    task_priority = models.IntegerField(default=10, validators=[MaxValueValidator(10), MinValueValidator(1)])
    is_robot = models.BooleanField(default=False)

    # meta
    class Meta:
        verbose_name_plural = "User Profiles"
