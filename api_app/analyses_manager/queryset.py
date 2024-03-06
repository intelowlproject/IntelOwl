from api_app.queryset import CleanOnCreateQuerySet, ModelWithOwnershipQuerySet


class AnalysisQuerySet(CleanOnCreateQuerySet, ModelWithOwnershipQuerySet):
    ...
