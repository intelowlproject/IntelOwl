import datetime
from collections import defaultdict

from django.contrib.contenttypes.models import ContentType
from django.db.models import Case, DurationField, ExpressionWrapper, F, Q, QuerySet, Value, When
from django.db.models.functions import Power
from django.db.models.lookups import IRegex, Range
from django.utils.timezone import now

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.choices import DecayProgressionEnum


class UserEventQuerySet(QuerySet):
    def decay(self):
        objects = (
            self.exclude(decay_progression=DecayProgressionEnum.FIXED.value)
            .exclude(next_decay__isnull=True)
            .filter(next_decay__lte=now())
        )

        count = objects.count()
        if not count:
            return 0

        # Step 1: Bulk update decay_times and next_decay on UserEvent
        objects.update(
            decay_times=F("decay_times") + 1,
            next_decay=Case(
                When(
                    data_model__reliability=1,
                    then=None,
                ),
                When(
                    decay_progression=DecayProgressionEnum.LINEAR.value,
                    then=F("next_decay") + ExpressionWrapper(
                        F("decay_timedelta_days") * datetime.timedelta(days=1),
                        output_field=DurationField(),
                    ),
                ),
                When(
                    decay_progression=DecayProgressionEnum.INVERSE_EXPONENTIAL.value,
                    then=F("next_decay") + ExpressionWrapper(
                        Power(
                            F("decay_timedelta_days"),
                            F("decay_times") + 1,
                        ) * datetime.timedelta(days=1),
                        output_field=DurationField(),
                    ),
                ),
                default=None,
            ),
        )

        # Step 2: Bulk update reliability on data_model
        # Group by content_type to handle GenericForeignKey correctly
        content_type_ids = defaultdict(list)
        for obj in objects.values("data_model_content_type_id", "data_model_object_id"):
            content_type_ids[obj["data_model_content_type_id"]].append(
                obj["data_model_object_id"]
            )

        for ct_id, obj_ids in content_type_ids.items():
            ct = ContentType.objects.get_for_id(ct_id)
            model = ct.model_class()
            model.objects.filter(
                pk__in=obj_ids,
                reliability__gt=0,
            ).update(reliability=F("reliability") - 1)

        return count

    def visible_for_user(self, user):
        if user.has_membership():
            user_query = Q(user=user) | Q(
                user__membership__organization_id=user.membership.organization_id
            )
        else:
            user_query = Q(user=user)
        return self.filter(user_query)

    def create(self, **kwargs):
        obj = self.model(**kwargs)
        self._for_write = True
        if obj.data_model.reliability != 0:
            obj.next_decay = obj.date + datetime.timedelta(days=obj.decay_timedelta_days)
        obj.save(force_insert=True, using=self.db)
        return obj


class UserDomainWildCardEventQuerySet(UserEventQuerySet):
    def matches(self, analyzable: Analyzable) -> "UserDomainWildCardEventQuerySet":
        if analyzable.classification in [
            Classification.DOMAIN.value,
            Classification.URL.value,
        ]:
            return self.annotate(
                matches=IRegex(Value(analyzable.name), F("query"))
            ).filter(matches=True)
        return self.none()

    def create(self, **kwargs):
        instance = super().create(**kwargs)
        instance.analyzables.add(*instance.find_new_analyzables_from_query())
        return instance


class UserIPWildCardEventQuerySet(UserEventQuerySet):
    def matches(self, analyzable: Analyzable) -> "UserIPWildCardEventQuerySet":
        if analyzable.classification == Classification.IP.value:
            return self.annotate(
                matches=Range(Value(analyzable.name), (F("start_ip"), F("end_ip")))
            ).filter(matches=True)
        return self.none()

    def create(self, **kwargs):
        instance = super().create(**kwargs)
        instance.analyzables.add(*instance.find_new_analyzables_from_query())
        return instance
