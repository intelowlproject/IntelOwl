from django.conf import settings
from django.core.validators import MinLengthValidator
from django.db import models

# from rest_email_auth import app_settings
# from rest_email_auth.models import EmailConfirmation

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
    # meta
    class Meta:
        verbose_name_plural = "User Profiles"

    # contants
    DiscoverFromChoices = DiscoverFromChoices

    # fields

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="user_profile",
    )
    company_name = models.CharField(
        max_length=32, null=False, blank=False, validators=[MinLengthValidator(3)]
    )
    company_role = models.CharField(
        max_length=32, null=False, blank=False, validators=[MinLengthValidator(3)]
    )
    twitter_handle = models.CharField(
        max_length=16, null=True, blank=True, validators=[MinLengthValidator(3)]
    )
    discover_from = models.CharField(
        max_length=32,
        null=False,
        blank=False,
        choices=DiscoverFromChoices.choices,
        default=DiscoverFromChoices.OTHER,
    )
