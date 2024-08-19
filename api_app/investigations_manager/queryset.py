from api_app.queryset import CleanOnCreateQuerySet, ModelWithOwnershipQuerySet


class InvestigationQuerySet(CleanOnCreateQuerySet, ModelWithOwnershipQuerySet):
    ...
