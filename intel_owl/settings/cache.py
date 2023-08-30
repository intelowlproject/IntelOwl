# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import base64
import pickle
from typing import Any, Dict

from django.core.cache.backends.db import DatabaseCache
from django.db import connections, router
from django.utils.encoding import force_bytes


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
            cursor.execute(
                f"SELECT cache_key, value, expires FROM {table} "
                "WHERE cache_key LIKE %s",
                [query],
            )
            rows = cursor.fetchall()
        if len(rows) < 1:
            return {}
        return_d = {}
        for row in rows:
            value = connections[db].ops.process_clob(row[1])
            return_d[row[0]] = pickle.loads(base64.b64decode(force_bytes(value)))
        return return_d


CACHES = {
    "default": {
        "BACKEND": "intel_owl.settings.cache.DatabaseCacheExtended",
        "LOCATION": "intelowl_cache",
        "KEY_FUNCTION": "intel_owl.settings.cache.plain_key",
    }
}
