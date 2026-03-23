import datetime

from django.db.models import F, Q, QuerySet, Value
from django.db.models.lookups import IRegex, Range
from django.utils.timezone import now

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.choices import DecayProgressionEnum


class UserEventQuerySet(QuerySet):
    def decay(self):
        from django.contrib.contenttypes.models import ContentType
        from django.db.models import Case, DurationField, ExpressionWrapper, F, Value, When
        from django.db.models.fields import DateTimeField as DateTimeModelField
        from django.db.models.functions import Power

        objects_qs = (
            self.exclude(decay_progression=DecayProgressionEnum.FIXED.value)
            .exclude(next_decay__isnull=True)
            .filter(next_decay__lte=now())
        )

        # Materialise the qualifying PKs once so that later mutations
        # (which change next_decay / reliability) do not shift the set.
        event_data = list(
            objects_qs.values("pk", "data_model_content_type", "data_model_object_id")
        )
        count = len(event_data)
        if not count:
            return 0

        all_pks = [row["pk"] for row in event_data]

        # --- Group data-model object IDs by their GenericForeignKey content-type ---
        ct_to_group: dict = {}
        for row in event_data:
            ct_id = row["data_model_content_type"]
            dm_id = row["data_model_object_id"]
            if ct_id not in ct_to_group:
                ct_to_group[ct_id] = {"dm_ids": [], "pks_by_dm_id": {}}
            ct_to_group[ct_id]["dm_ids"].append(dm_id)
            ct_to_group[ct_id]["pks_by_dm_id"].setdefault(dm_id, []).append(row["pk"])

        # --- Find which events will have reliability drop to 0 ------------------
        # Those whose data_model currently has reliability == 1 need next_decay=None.
        zero_reliability_event_pks: list = []
        for ct_id, group in ct_to_group.items():
            ct = ContentType.objects.get_for_id(ct_id)
            model_class = ct.model_class()
            zero_dm_ids = set(
                model_class.objects.filter(
                    pk__in=group["dm_ids"], reliability=1
                ).values_list("pk", flat=True)
            )
            for dm_id in zero_dm_ids:
                zero_reliability_event_pks.extend(
                    group["pks_by_dm_id"].get(dm_id, [])
                )

        # --- Build Case/When expressions for next_decay -------------------------
        # one_day is the unit multiplier that converts an integer day-count to
        # a PostgreSQL interval (integer * interval = interval).
        one_day = Value(datetime.timedelta(days=1), output_field=DurationField())

        next_decay_whens = []
        if zero_reliability_event_pks:
            next_decay_whens.append(
                When(pk__in=zero_reliability_event_pks, then=Value(None))
            )
        next_decay_whens += [
            # LINEAR: advance next_decay by decay_timedelta_days days.
            When(
                decay_progression=DecayProgressionEnum.LINEAR.value,
                then=ExpressionWrapper(
                    F("next_decay") + F("decay_timedelta_days") * one_day,
                    output_field=DateTimeModelField(),
                ),
            ),
            # INVERSE_EXPONENTIAL: advance by decay_timedelta_days^(decay_times+2) days.
            # The original loop does `decay_times += 1` first, then reads `decay_times+1`,
            # so the effective exponent against the *pre-update* column value is +2.
            When(
                decay_progression=DecayProgressionEnum.INVERSE_EXPONENTIAL.value,
                then=ExpressionWrapper(
                    F("next_decay")
                    + Power(F("decay_timedelta_days"), F("decay_times") + Value(2))
                    * one_day,
                    output_field=DateTimeModelField(),
                ),
            ),
        ]

        # --- Single bulk UPDATE on all qualifying UserEvent rows ----------------
        self.model.objects.filter(pk__in=all_pks).update(
            decay_times=F("decay_times") + 1,
            next_decay=Case(
                *next_decay_whens,
                default=F("next_decay"),
                output_field=DateTimeModelField(),
            ),
        )

        # --- Per-content-type bulk UPDATE on data_model reliability -------------
        # data_model is a GenericForeignKey so we group by content-type and issue
        # one UPDATE per concrete model class (≤ 3 in practice).
        for ct_id, group in ct_to_group.items():
            ct = ContentType.objects.get_for_id(ct_id)
            model_class = ct.model_class()
            model_class.objects.filter(
                pk__in=group["dm_ids"], reliability__gt=0
            ).update(reliability=F("reliability") - 1)

        return count

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
