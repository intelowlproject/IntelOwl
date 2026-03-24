from celery import shared_task


@shared_task
def scheduled_update_check():
    """
    Periodic task to check for IntelOwl updates.
    Intended to be triggered via celery beat.
    """
    from api_app.core.update_checker import check_for_update  # lazy import

    check_for_update()
