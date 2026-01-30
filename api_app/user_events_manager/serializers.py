import ipaddress
import logging

from django.db import transaction
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzables_manager.serializers import AnalyzableSerializer
from api_app.choices import Classification
from api_app.data_model_manager.models import DomainDataModel, IPDataModel
from api_app.data_model_manager.serializers import (
    DataModelRelatedField,
    DomainDataModelSerializer,
    IPDataModelSerializer,
)
from api_app.user_events_manager.models import (
    UserAnalyzableEvent,
    UserDomainWildCardEvent,
    UserIPWildCardEvent,
)
from api_app.user_events_manager.validators import validate_ipv4_network

logger = logging.getLogger(__name__)


class UserEventSerializer(serializers.ModelSerializer):
    user = serializers.CharField(source="user.username", allow_null=False, read_only=True)

    date = serializers.DateTimeField(read_only=True)

    next_decay = serializers.DateTimeField(read_only=True)
    decay_times = serializers.IntegerField(read_only=True)

    class Meta:
        fields = serializers.ALL_FIELDS

    def validate(self, data):
        if "request" not in self.context:
            raise ValidationError("A request context is required")
        data["user"] = self.context["request"].user
        return data


class UserAnalyzableEventSerializer(UserEventSerializer):
    analyzable = AnalyzableSerializer(required=True)
    data_model_content = serializers.JSONField(write_only=True, source="data_model")
    data_model = DataModelRelatedField(read_only=True)

    class Meta:
        model = UserAnalyzableEvent
        fields = serializers.ALL_FIELDS

    def is_valid(self, *, raise_exception=False):
        res = super().is_valid(raise_exception=raise_exception)
        classification = Classification.calculate_observable(self._validated_data["analyzable"]["name"])
        if classification == Classification.GENERIC:
            raise ValidationError("Cannot create an user event for a generic")
        serializer_class = Classification.get_data_model_class(
            classification=classification,
        ).get_serializer()
        serializer = serializer_class(data=self.initial_data["data_model_content"])
        res2 = serializer.is_valid(raise_exception=raise_exception)
        self._errors.update(serializer.errors)
        self._validated_data["data_model_content"] = serializer
        self._validated_data["analyzable"]["classification"] = classification
        logger.debug(f"{self._validated_data=}")
        return res and res2

    def save(self, **kwargs):
        with transaction.atomic():
            analyzable = self.validated_data["analyzable"]
            an, _ = Analyzable.objects.get_or_create(
                name=analyzable["name"], classification=analyzable["classification"]
            )
            data_model = self.validated_data.pop("data_model_content").save()
            return super().save(**kwargs, data_model=data_model, analyzable=an)


class UserDomainWildCardEventSerializer(UserEventSerializer):
    query = serializers.CharField(required=True)
    analyzables = serializers.PrimaryKeyRelatedField(read_only=True, many=True)
    data_model_content = DomainDataModelSerializer(write_only=True, source="data_model")
    data_model = DomainDataModelSerializer(read_only=True)

    class Meta:
        model = UserDomainWildCardEvent
        fields = serializers.ALL_FIELDS

    def save(self, **kwargs):
        with transaction.atomic():
            data_model = DomainDataModel.objects.create(**self.validated_data.pop("data_model"))
            return super().save(**kwargs, data_model=data_model)


class UserIPWildCardEventSerializer(UserEventSerializer):
    analyzables = serializers.PrimaryKeyRelatedField(read_only=True, many=True)
    data_model_content = IPDataModelSerializer(write_only=True, source="data_model")
    data_model = IPDataModelSerializer(read_only=True)
    start_ip = serializers.IPAddressField(read_only=True)
    end_ip = serializers.IPAddressField(read_only=True)
    network = serializers.CharField(write_only=True, validators=[validate_ipv4_network])

    def validate(self, data):
        network = data.pop("network")
        network = ipaddress.IPv4Network(network)
        data["start_ip"] = str(network[0])
        data["end_ip"] = str(network[-1])
        return super().validate(data)

    class Meta:
        model = UserIPWildCardEvent
        fields = serializers.ALL_FIELDS

    def save(self, **kwargs):
        with transaction.atomic():
            data_model = IPDataModel.objects.create(**self.validated_data.pop("data_model"))
            return super().save(**kwargs, data_model=data_model)
