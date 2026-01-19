import logging

from django.conf import settings
from rest_framework import serializers as rfs
from rest_framework.exceptions import ValidationError
from rest_framework.fields import Field

from api_app.interfaces import OwnershipAbstractModel
from certego_saas.apps.organization.organization import Organization
from certego_saas.ext.upload.elastic import BISerializer
from intel_owl.settings._util import get_environment

logger = logging.getLogger(__name__)


class AbstractBIInterface(BISerializer):
    application = rfs.CharField(read_only=True, default="IntelOwl")
    environment = rfs.SerializerMethodField(method_name="get_environment")
    username: Field
    class_instance = rfs.SerializerMethodField(
        read_only=True, method_name="get_class_instance"
    )
    process_time: Field
    status: Field
    end_time: Field
    job_id: Field

    class Meta:
        fields = BISerializer.Meta.fields + [
            "username",
            "class_instance",
            "process_time",
            "status",
            "end_time",
            "job_id",
        ]

    @staticmethod
    def get_class_instance(instance):
        return instance.__class__.__name__.lower()

    @staticmethod
    def get_environment(instance):
        # we cannot pass directly the function to the serializer's field
        # for this reason we need a function that call another function
        return get_environment()

    @staticmethod
    def get_index():
        return settings.ELASTICSEARCH_BI_INDEX


class ModelWithOwnershipSerializer(rfs.ModelSerializer):
    class Meta:
        model = OwnershipAbstractModel
        fields = ("for_organization", "owner")
        abstract = True

    owner = rfs.HiddenField(default=rfs.CurrentUserDefault())
    organization = rfs.SlugRelatedField(
        queryset=Organization.objects.all(),
        required=False,
        allow_null=True,
        slug_field="name",
        write_only=True,
        default=None,
    )

    def validate(self, attrs):
        logger.debug(f"{attrs=}")
        org = attrs.pop("organization", None)
        if org:
            # 1 - we are owner  OR
            # 2 - we are admin of the same org
            if org.owner == attrs["owner"] or (
                attrs["owner"].has_membership()
                and attrs["owner"].membership.organization.pk == org.pk
                and attrs["owner"].membership.is_admin
            ):
                attrs["for_organization"] = True
            else:
                raise ValidationError(
                    {"detail": "You are not owner or admin of the organization"}
                )
        logger.debug(f"{attrs=}")
        return super().validate(attrs)

    def to_representation(self, instance: OwnershipAbstractModel):
        result = super().to_representation(instance)
        result["owner"] = instance.owner.username if instance.owner else None
        return result
