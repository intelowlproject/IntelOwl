from api_app.queryset import ModelWithOwnershipQuerySet, CleanOnCreateQuerySet


class AnalysisQuerySet(CleanOnCreateQuerySet, ModelWithOwnershipQuerySet):
    ...