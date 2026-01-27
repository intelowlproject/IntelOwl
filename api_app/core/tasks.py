from celery import shared_task

from api_app.core.update_checker import check_for_update


@shared_task
def scheduled_update_check():
    """
    Periodic task to check for IntelOwl updates.
    Intended to be triggered via celery beat.
    """
    check_for_update()
