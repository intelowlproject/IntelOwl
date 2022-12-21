# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging

from django.core import serializers
from django.contrib.auth import get_user_model
from rest_framework import serializers as rfs

from api_app.analyzers_manager.constants import AllTypes
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.connectors_manager.serializers import ConnectorConfigSerializer
from api_app.core.serializers import AbstractConfigSerializer
from api_app.models import Job
from certego_saas.apps.organization.permissions import IsObjectOwnerOrSameOrgPermission

from .models import CachedPlaybook

logger = logging.getLogger(__name__)

User = get_user_model


class PlaybookConfigSerializer(AbstractConfigSerializer):
    """
    Serializer for `playbook_config.json`.
    """

    CONFIG_FILE_NAME = "playbook_config.json"

    config = rfs.DictField(default={})
    secrets = rfs.DictField(default={})
    params = rfs.DictField(default={})
    python_module = rfs.CharField(default="")
    # automatically populated fields
    verification = rfs.DictField(default={})

    # Required fields
    description = rfs.CharField()
    analyzers = rfs.DictField(child=rfs.DictField())
    connectors = rfs.DictField(child=rfs.DictField())

    # Optional Fields
    supports = rfs.ListField(
        child=rfs.ChoiceField(choices=AllTypes.values),
        required=False,
        default=[],
    )

    @classmethod
    def _cached_playbooks(cls, user: User, show_all=False) -> dict:
        """
        Returns config file as `dict`.
        """
        config = super()._read_config()

        cached_playbooks = CachedPlaybook.objects.all()
        # owner_org = user.membership

        cached_serialized_playbooks = serializers.serialize(
            "json", [obj for obj in cached_playbooks]
        )
        cached_playbooks_model_json = json.loads(cached_serialized_playbooks)
        if len(cached_playbooks_model_json) == 0:
            # this is for when no playbooks are cached
            return config

        cached_playbooks_final = {}
        for playbook in cached_playbooks_model_json:
            whitelisted_organization = playbook.get("fields").get("organization")
            owner = playbook.get("fields").get("owner")

            # when show_all is used, no other factors are considered.
            # all playbooks are simply listed out.
            if show_all:
                cached_playbooks_final[playbook["pk"]] = playbook["fields"]
                continue

            elif owner is not None and whitelisted_organization is not None:
                user_org = None
                if user.has_membership():
                    user_org = user.membership

                if user == owner or whitelisted_organization == user_org:
                    cached_playbooks_final[playbook["pk"]] = playbook["fields"]
            else:
                cached_playbooks_final[playbook["pk"]] = playbook["fields"]

        return cached_playbooks_final

    @classmethod
    def output_with_cached_playbooks(cls, user, show_all=False) -> dict:
        original_config_dict = cls.read_and_verify_config()
        config_dict = cls._cached_playbooks(user, show_all=show_all)
        serializer_errors = {}
        for key, config in config_dict.items():
            new_config = {"name": key, **config}
            serializer = cls(data=new_config)  # lgtm [py/call-to-non-callable]
            if serializer.is_valid():
                config_dict[key] = serializer.data
            else:
                serializer_errors[key] = serializer.errors

        if bool(serializer_errors):
            logger.error(f"{cls.__name__} serializer failed: {serializer_errors}")
            raise rfs.ValidationError(serializer_errors)

        config_dict = config_dict | original_config_dict
        return config_dict


class CachedPlaybooksSerializer(rfs.ModelSerializer):
    job_id = rfs.IntegerField()
    name = rfs.CharField(max_length=225)
    description = rfs.CharField(max_length=225)
    organization_mode = rfs.BooleanField(default=False)

    class Meta:
        model = CachedPlaybook
        fields = (
            "name",
            "description",
            "analyzers",
            "connectors",
            "supports",
            "disabled",
            "owner",
            "organization",
            "organization_mode",
            "job_id",
        )

    def validate(self, attrs: dict) -> dict:
        # The playbook in the playbook_config.json file is given more
        # priority if the same named one is ever added back again.

        attrs = super().validate(attrs)
        playbook_name = attrs["name"].replace(" ", "_").upper()
        job_id = attrs.get("job_id")

        job = Job.objects.get(pk=job_id)
        request = self.context.get("request", None)

        has_perm = IsObjectOwnerOrSameOrgPermission().has_object_permission(
            request, None, job
        )

        if not has_perm:
            raise rfs.ValidationError(
                "User doesn't have necessary permissions for this action."
            )

        analyzers_used = job.analyzers_to_execute
        connectors_used = job.connectors_to_execute

        analyzers = {analyzer: {} for analyzer in analyzers_used}
        connectors = {connector: {} for connector in connectors_used}

        supports = []
        existing_playbooks = PlaybookConfigSerializer.output_with_cached_playbooks(
            user=None, 
            show_all=True
        )

        existing_playbook = existing_playbooks.get(playbook_name, {})

        if existing_playbook != {}:
            raise rfs.ValidationError("Another playbook exists with that name.")

        analyzer_config = AnalyzerConfigSerializer.read_and_verify_config()
        for analyzer_ in analyzers:
            analyzer_checked = analyzer_config.get(analyzer_)
            if analyzer_checked is None:
                logger.info(f"Invalid analyzer {analyzer_}")
            type_ = analyzer_checked.get("type")
            if type_ == "file":
                if type_ in supports:
                    continue
                supports.append(type_)
            else:
                observable_supported = analyzer_checked.get("observable_supported")
                for observable_type in observable_supported:
                    if observable_type not in supports:
                        supports.append(observable_type)

        connector_config = ConnectorConfigSerializer.read_and_verify_config()
        for connector_ in connectors:
            connector_checked = connector_config.get(connector_)
            if connector_checked is None:
                logger.info(f"Invalid connector {connector_}")

        attrs["analyzers"] = analyzers
        attrs["connectors"] = connectors
        attrs["supports"] = supports
        attrs["name"] = playbook_name

        return attrs

    def create(self, validated_data: dict) -> CachedPlaybook:
        playbook_name = validated_data.get("name")
        analyzers = validated_data.get("analyzers")
        connectors = validated_data.get("connectors")
        supports = validated_data.get("supports")
        playbook_description = validated_data.get("description")
        job_id = validated_data.get("job_id")
        disabled = validated_data.get("disabled")
        organization_mode = validated_data.get("organization_mode")

        request = self.context.get("request", None)
        owner = request.user

        job = Job.objects.filter(pk=job_id).first()

        if job is None:
            raise rfs.ValidationError(f"Job of {job_id} doesn't exist.")

        organization = None
        if organization_mode and owner.has_membership():
            organization = request.user.membership

        if organization is None and organization_mode:
            raise rfs.ValidationError(
                "Can't use organization mode without user being in an organization!"
            )

        playbook = self.Meta.model.objects.create(
            name=playbook_name,
            analyzers={analyzer: {} for analyzer in analyzers},
            connectors={connector: {} for connector in connectors},
            supports=supports,
            description=playbook_description,
            disabled=disabled if type(disabled) == bool else False,
            owner=owner,
            organization=organization
        )

        return playbook
