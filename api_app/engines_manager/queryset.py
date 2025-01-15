from typing import List

from django.db.models import QuerySet


class EngineQuerySet(QuerySet):

    def enabled(self):
        # - prendo tutte le config
        # - prendo l'ereditarieta'
        # - vado a togliere dalle config, quelli che sono in eredita' di altri
        # - rimangono solo le ultime
        to_exclude = set()
        for config in self:
            class_ = config.python_module.python_class
            ancestors = class_.__mro__[1:]

            to_exclude.update(ancestors)
        return self.exclude(
            python_module__base_path="whatever",
            python_module__module__in=[
                f"{ancestor.__module__}.{ancestor.__name__}" for ancestor in to_exclude
            ],
        )

    def flatten(self) -> List["Engine"]:
        """
        Previous model

        :return:
        """
        # TODo optimize
        result = []
        objects = list(self)
        while True:
            added = False
            for i in range(
                len(objects) - 1,
                -1,
                -1,
            ):
                obj = objects[i]
                if not obj.dependencies:
                    result.append(obj)
                    added = True
                    del objects[i]
                    continue
                for dependency in obj.dependencies:
                    # we can't add this now
                    if dependency not in result:
                        continue
                # all the dependency are met
                result.append(obj)
                added = True
                del objects[i]
            # we have not added any new object at the result, we have a cycle
            if not added:
                raise RuntimeError("We found a cycle")
