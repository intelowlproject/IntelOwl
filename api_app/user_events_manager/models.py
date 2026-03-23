from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import ForeignKey, GenericIPAddressField
from django.db.models.functions import Cast
from django.utils.timezone import now

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzables_manager.queryset import AnalyzableQuerySet
from api_app.choices import Classification
from api_app.data_model_manager.models import DomainDataModel, IPDataModel
from api_app.user_events_manager.choices import DecayProgressionEnum
from api_app.user_events_manager.queryset import (
    UserDomainWildCardEventQuerySet,
    UserEventQuerySet,
    UserIPWildCardEventQuerySet,
)


class UserEvent(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    date = models.DateTimeField(default=now, editable=False, db_index=True)
    reason = models.CharField(max_length=256, default="", null=True)
    data_model: ForeignKey

    decay_progression = models.IntegerField(
        choices=DecayProgressionEnum.choices, default=DecayProgressionEnum.FIXED.value
    )
    decay_timedelta_days = models.PositiveIntegerField(default=0)

    # internal usage
    next_decay = models.DateTimeField(default=None, editable=False, null=True, db_index=True, blank=True)
    decay_times = models.PositiveIntegerField(default=0, editable=False)

    objects = UserEventQuerySet.as_manager()

    class Meta:
        abstract = True

    def clean(self):
        super().clean()
        if self.decay_progression == DecayProgressionEnum.FIXED.value and self.decay_timedelta_days != 0:
            raise ValidationError("You cant have a fixed decay progression and timedelta different from 0")


class UserAnalyzableEvent(UserEvent):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="analyzable_events",
    )
    analyzable = models.ForeignKey(
        Analyzable, on_delete=models.CASCADE, editable=False, related_name="user_events"
    )
    data_model_content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        limit_choices_to={
            "app_label": "data_model_manager",
        },
        editable=False,
    )
    data_model_object_id = models.PositiveIntegerField(editable=False)
    data_model = GenericForeignKey("data_model_content_type", "data_model_object_id")

    decay_progression = models.IntegerField(
        choices=DecayProgressionEnum.choices, default=DecayProgressionEnum.LINEAR.value
    )
    decay_timedelta_days = models.PositiveIntegerField(default=7)

    class Meta:
        unique_together = (("user", "analyzable"),)
        indexes = [models.Index(fields=["data_model_content_type", "data_model_object_id"])]

    def clean(self):
        super().clean()
        if self.data_model.__class__ is not self.analyzable.get_data_model_class():
            raise ValidationError("Data model class does not match analyzable type")


class UserDomainWildCardEvent(UserEvent):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="analyzable_domain_wildcard_events",
    )

    query = models.CharField(max_length=100, editable=False, help_text="This use classic regex syntax")
    analyzables = models.ManyToManyField(
        Analyzable,
        related_name="user_domain_wildcard_events",
        editable=False,
        limit_choices_to={
            "classification__in": [
                Classification.DOMAIN.value,
                Classification.URL.value,
            ]
        },
    )

    data_model = models.ForeignKey(
        DomainDataModel,
        on_delete=models.CASCADE,
        related_name="domain_wildcard_events",
        editable=False,
    )

    objects = UserDomainWildCardEventQuerySet.as_manager()

    class Meta:
        unique_together = (("user", "query"),)

    def find_new_analyzables_from_query(self) -> AnalyzableQuerySet:
        return Analyzable.objects.filter(
            name__iregex=self.query,
            classification__in=[Classification.URL.value, Classification.DOMAIN.value],
        ).exclude(pk__in=self.analyzables.values_list("pk", flat=True))


class UserIPWildCardEvent(UserEvent):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="analyzable_ip_wildcard_events",
    )
    start_ip = models.GenericIPAddressField()
    end_ip = models.GenericIPAddressField()
    analyzables = models.ManyToManyField(
        Analyzable,
        related_name="user_ip_wildcard_events",
        editable=False,
        limit_choices_to={"classification": Classification.IP.value},
    )
    data_model = models.ForeignKey(
        IPDataModel,
        on_delete=models.CASCADE,
        related_name="ip_wildcard_events",
        editable=False,
    )

    objects = UserIPWildCardEventQuerySet.as_manager()

    class Meta:
        unique_together = (("user", "start_ip", "end_ip"),)

    def find_new_analyzables_from_query(self) -> AnalyzableQuerySet:
        return (
            Analyzable.objects.filter(classification=Classification.IP.value)
            .annotate(ip=Cast("name", GenericIPAddressField()))
            .filter(ip__gte=self.start_ip, ip__lte=self.end_ip)
            .exclude(pk__in=self.analyzables.values_list("pk", flat=True))
        )
