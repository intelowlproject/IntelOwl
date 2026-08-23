    @property
    def total_jobs(self) -> int:
        from django.db.models import Q

        paths = list(self.jobs.values_list("path", flat=True))
        if not paths:
            return 0
        # Count every job whose tree contains at least one of the
        # investigation's root jobs using treebeard's materialized
        # path (path prefix match) — one query instead of N+1
        query = Q(path__startswith=paths[0])
        for path in paths[1:]:
            query |= Q(path__startswith=path)
        return Job.objects.filter(query).count()
