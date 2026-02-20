# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import datetime
from collections import defaultdict

from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import Case, ExpressionWrapper, F, Q, QuerySet, Value, When
from django.db.models import DurationField
from django.db.models.functions import Power
from django.db.models.lookups import IRegex, Range
from django.utils.timezone import now

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.choices import DecayProgressionEnum


class UserEventQuerySet(QuerySet):
    def decay(self):
        """
        Bulk-decay all eligible UserEvents to eliminate N+1 queries.

        For ForeignKey data_model (wildcard events): uses pure SQL update()
        with F() expressions and Case/When for zero queries per event.

        For GenericForeignKey data_model (analyzable events): uses bulk_update
        grouped by concrete class — unavoidable due to Django ORM limitations
        with GenericForeignKey.

        Returns the number of events decayed.
        """
        objects = (
            self.exclude(decay_progression=DecayProgressionEnum.FIXED.value)
            .exclude(next_decay__isnull=True)
            .filter(next_decay__lte=now())
        )

        if not objects.exists():
            return 0

        # Check if data_model is a real ForeignKey (wildcard events)
        # or a GenericForeignKey (analyzable events)
        model_fields = {field.name for field in self.model._meta.fields}

        if "data_model" in model_fields:
            # ForeignKey case: pure SQL approach
            return self._decay_with_fk(objects)
        else:
            # GenericForeignKey case: bulk_update approach
            return self._decay_with_gfk(objects)

    def _decay_with_fk(self, objects):
        """
        Pure SQL decay for wildcard events (ForeignKey data_model).
        Uses update() + F() + Case/When + Power() for minimal queries.
        """
        count = objects.count()
        if not count:
            return 0

        with transaction.atomic():
            # Update data_model reliability in a single query
            objects.filter(
                data_model__reliability__gt=0
            ).values("data_model").distinct().update(
                **{"data_model__reliability": F("data_model__reliability") - 1}
            )

            # Update event fields using Case/When for conditional logic
            objects.update(
                decay_times=F("decay_times") + 1,
                next_decay=Case(
                    # reliability hit 0 -> stop decay
                    When(
                        data_model__reliability__lte=0,
                        then=None,
                    ),
                    # LINEAR decay
                    When(
                        decay_progression=DecayProgressionEnum.LINEAR.value,
                        then=ExpressionWrapper(
                            F("next_decay")
                            + ExpressionWrapper(
                                F("decay_timedelta_days")
                                * Value(datetime.timedelta(days=1)),
                                output_field=DurationField(),
                            ),
                            output_field=DurationField(),
                        ),
                    ),
                    # INVERSE_EXPONENTIAL decay
                    When(
                        decay_progression=DecayProgressionEnum.INVERSE_EXPONENTIAL.value,
                        then=ExpressionWrapper(
                            F("next_decay")
                            + ExpressionWrapper(
                                Power(F("decay_timedelta_days"), F("decay_times") + 1)
                                * Value(datetime.timedelta(days=1)),
                                output_field=DurationField(),
                            ),
                            output_field=DurationField(),
                        ),
                    ),
                    default=None,
                ),
            )

        return count

    def _decay_with_gfk(self, objects):
        """
        Bulk decay for analyzable events (GenericForeignKey data_model).
        GenericForeignKey cannot be updated via F() expressions in SQL,
        so we use bulk_update grouped by concrete class.
        """
        objects = objects.prefetch_related("data_model")
        events = list(objects)
        if not events:
            return 0

        data_models_by_class = defaultdict(list)

        for event in events:
            event.decay_times += 1
            data_model = event.data_model

            if data_model is not None:
                data_model.reliability -= 1

            if data_model is None or data_model.reliability <= 0:
                event.next_decay = None
            else:
                if event.decay_progression == DecayProgressionEnum.LINEAR.value:
                    event.next_decay += datetime.timedelta(days=event.decay_timedelta_days)
                elif event.decay_progression == DecayProgressionEnum.INVERSE_EXPONENTIAL.value:
                    event.next_decay += datetime.timedelta(
                        days=event.decay_timedelta_days**event.decay_times
                    )

            if data_model is not None:
                data_models_by_class[data_model.__class__].append(data_model)

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
