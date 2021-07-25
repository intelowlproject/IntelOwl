from django.core.cache import cache

from intel_owl import celery as celery_app


def kill_running_plugin(key: str, plugin: str) -> None:
    task_id_map = cache.get(key)
    print("inside controller", key, task_id_map)
    if isinstance(task_id_map, dict):
        if plugin == "__all__":
            task_ids = list(task_id_map.values())
            task_id_map = {}
        elif plugin in task_id_map:
            task_ids = [task_id_map[plugin]]
            task_id_map.pop(plugin)

        celery_app.control.revoke(task_ids)
        # unset cache if empty else reset
        if not bool(task_id_map):
            cache.delete(key)
        else:
            cache.set(key, task_id_map)
