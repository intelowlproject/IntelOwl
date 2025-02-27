from celery import shared_task

from api_app.user_events_manager.choices import DecayProgressionEnum
from api_app.user_events_manager.models import UserAnalyzableEvent, UserDomainWildCardEvent, UserIPWildCardEvent
from intel_owl.tasks import FailureLoggedTask


@shared_task(base=FailureLoggedTask, soft_time_limit=300)
def user_events_decay():
    UserAnalyzableEvent.objects.decay()
    UserDomainWildCardEvent.objects.decay()
    UserIPWildCardEvent.objects.decay()