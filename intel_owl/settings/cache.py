# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Any, Dict

from django.core.cache.backends.db import DatabaseCache
from django.db import ProgrammingError, connections, router


def plain_key(key, key_prefix, version):
    return key  # just return the key without doing anything


class DatabaseCacheExtended(DatabaseCache):
    """
    Reference SO:
    https://stackoverflow.com/questions/37621392/enumerating-keys-in-django-database-cache
    """

    def get_where(self, starts_with: str, version=None) -> Dict[str, Any]:
        """
        Usage: cache.get_where('string%')
        """
        db = router.db_for_read(self.cache_model_class)
        table = connections[db].ops.quote_name(self._table)
        query = self.make_and_validate_key(starts_with + "%", version=version)
        with connections[db].cursor() as cursor:
            try:
                cursor.execute(
                    f"SELECT cache_key, value, expires FROM {table} WHERE cache_key LIKE %s",
                    [query],
                )
            except ProgrammingError:
                return {}
            rows = cursor.fetchall()
        if len(rows) < 1:
            return {}
        return self.get_many([row[0] for row in rows], version=version)


CACHES = {
    "default": {
        "BACKEND": "intel_owl.settings.cache.DatabaseCacheExtended",
        "LOCATION": "intelowl_cache",
        "KEY_FUNCTION": "intel_owl.settings.cache.plain_key",
    }
}
