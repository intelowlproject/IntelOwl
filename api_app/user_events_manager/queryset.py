import datetime

from django.db.models import F, Q, QuerySet, Value
from django.db.models.lookups import IRegex, Range
from django.utils.timezone import now

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.choices import DecayProgressionEnum


class UserEventQuerySet(QuerySet):
    def decay(self):
        from collections import defaultdict

        from django.db import transaction

        objects = (
            self.exclude(decay_progression=DecayProgressionEnum.FIXED.value)
            .exclude(next_decay__isnull=True)
            .filter(
                next_decay__lte=now(),
            )
        )
        # ForeignKey appears in _meta.fields (wildcard models) -> use JOIN.
        # GenericForeignKey does not (UserAnalyzableEvent) -> use prefetch.
        model_fields = {field.name for field in self.model._meta.fields}
        if "data_model" in model_fields:
            objects = objects.select_related("data_model")
        else:
            objects = objects.prefetch_related("data_model")

        # Load into memory so we can mutate fields and bulk-write back.
        events = list(objects)
        if not events:
            return 0

        # Group by concrete class since bulk_update works per-table.
        data_models_by_class = defaultdict(list)

        for obj in events:
            obj.decay_times += 1
            data_model = obj.data_model

            if data_model is not None:
                data_model.reliability -= 1

            if data_model is None or data_model.reliability == 0:
                obj.next_decay = None
            else:
                if obj.decay_progression == DecayProgressionEnum.LINEAR.value:
                    obj.next_decay += datetime.timedelta(days=obj.decay_timedelta_days)
                elif obj.decay_progression == DecayProgressionEnum.INVERSE_EXPONENTIAL.value:
                    obj.next_decay += datetime.timedelta(
                        days=obj.decay_timedelta_days ** (obj.decay_times + 1)
                    )

            if data_model is not None:
                data_models_by_class[data_model.__class__].append(data_model)

        # Bulk-write instead of per-object .save() to avoid O(N) queries.
        # Atomic so partial failures don't leave inconsistent state.
        with transaction.atomic():
            for model_class, models_list in data_models_by_class.items():
                model_class.objects.bulk_update(models_list, ["reliability"])
            self.model.objects.bulk_update(events, ["decay_times", "next_decay"])

        return len(events)

    def visible_for_user(self, user):
        if user.has_membership():
            user_query = Q(user=user) | Q(user__membership__organization_id=user.membership.organization_id)
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
            return self.annotate(matches=IRegex(Value(analyzable.name), F("query"))).filter(matches=True)
        return self.none()

    def create(self, **kwargs):
        instance = super().create(**kwargs)
        instance.analyzables.add(*instance.find_new_analyzables_from_query())
        return instance


class UserIPWildCardEventQuerySet(UserEventQuerySet):
    def matches(self, analyzable: Analyzable) -> "UserIPWildCardEventQuerySet":
        if analyzable.classification == Classification.IP.value:
            return self.annotate(matches=Range(Value(analyzable.name), (F("start_ip"), F("end_ip")))).filter(
                matches=True
            )
        return self.none()

    def create(self, **kwargs):
        instance = super().create(**kwargs)
        instance.analyzables.add(*instance.find_new_analyzables_from_query())
        return instance
