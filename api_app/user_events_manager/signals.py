import ipaddress
import logging
from django.db import models
from django.dispatch import receiver
from django.utils.timezone import now

from .models import (
    UserAnalyzableEvent,
    UserDomainWildCardEvent,
    UserIPWildCardEvent,
    UserEvent,
)

logger = logging.getLogger(__name__)


@receiver(models.signals.post_delete, sender=UserDomainWildCardEvent)
@receiver(models.signals.post_delete, sender=UserIPWildCardEvent)
@receiver(models.signals.post_delete, sender=UserAnalyzableEvent)
def post_delete_event_delete_data_model(
    sender, instance: UserDomainWildCardEvent, **kwargs
):
    instance.data_model.delete()


@receiver(models.signals.post_delete, sender=UserDomainWildCardEvent)
@receiver(models.signals.post_delete, sender=UserIPWildCardEvent)
@receiver(models.signals.post_save, sender=UserAnalyzableEvent)
def post_save_event_analyzable_quokka_signal(sender, instance: UserEvent, **kwargs):
    """
    { "action" : "set_false_positive",
    "value" : "google.com",
    "external_links" : [],
    "reason": "",
    "source" : ""
    },
    { "action" : "set_clean",
    "value" : "google.com",
    "external_links" : [],
    "reason": "",
    "source" : ""
    }
    { "action" : "set_observable_as_ioc"
    "value" : "google.com",
    "threat": "",
    "external_links" : [],
    "reliability_score": "A"
    "kill_chain_phase": ""
    "decay_in" 10,
    "forced_ip_only": True
    "forced_non_exportable": True
    "source" : ""
    }
    { "action" : "set_abused",
    "value" : "google.com",
    "external_links" : [],
    "threat": "",
    "force_set_malicious": False
    "source" : ""
    }
    { "action" : "set_pup",
    "value" : "google.com",
    "external_links" : [],
    "threat": "",
    "force_set_malicious": False
    "source" : ""
    }
    """
    from api_app.data_model_manager.models import BaseDataModel

    dm: BaseDataModel = instance.data_model
    data = {
        "source": instance.user.username,
        "external_links": dm.external_references,
    }
    if isinstance(instance, UserAnalyzableEvent):
        if instance.analyzable.is_sample:
            # TODO fare i file
            return
        else:
            data["value"] = instance.analyzable.name
    elif isinstance(instance, UserIPWildCardEvent):
        data["value"] = str(
            list(
                ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(instance.start_ip),
                    ipaddress.IPv4Address(instance.end_ip),
                )
            )[0]
        )
    elif isinstance(instance, UserDomainWildCardEvent):
        data["value"] = instance.query

    if dm.TAGS.ABUSED.value in dm.tags:
        data["action"] = "set_abused"
        data["threat"] = ", ".join(dm.tags)
        if dm.evaluation == dm.EVALUATIONS.MALICIOUS.value and dm.reliability >= 7:
            data["force_set_malicious"] = True
    elif dm.evaluation == dm.EVALUATIONS.TRUSTED.value:
        data["reason"] = str(dm.additional_info)
        if dm.reliability >= 7:
            data["action"] = "set_false_positive"
        else:
            data["action"] = "set_clean"
    elif dm.evaluation == dm.EVALUATIONS.MALICIOUS.value:
        data["action"] = "set_observable_as_ioc"
        data["threat"] = ", ".join(dm.tags)
        data["kill_chain_phase"] = dm.kill_chain_phase
        data["decay_in"] = (instance.next_decay - now()).days
        if dm.TAGS.IP_ONLY.value in dm.tags:
            data["forced_ip_only"] = True
        if dm.TAGS.NOT_EXPORTABLE.value in dm.tags:
            data["forced_non_exportable"] = True

        if dm.reliability >= 9:
            data["reliability_score"] = "A"
        elif dm.reliability >= 7:
            data["reliability_score"] = "B"
        elif dm.reliability >= 5:
            data["reliability_score"] = "C"
        else:
            data["reliability_score"] = "D"
    logger.info(f"Data for quokka is {data}")
