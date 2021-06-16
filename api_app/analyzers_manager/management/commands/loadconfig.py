import json
from django.core.management.base import BaseCommand
from api_app.analyzers_manager.models import Analyzer, Secret


class Command(BaseCommand):
    help = "Loads the analyzer_config.json into the DB"

    def add_arguments(self, parser):
        parser.add_argument("json_file", type=str)

    def handle(self, *args, **options):
        config_objs = self.read_file(options["json_file"])

        self.append_to_db(config_objs)

    def append_to_db(self, config_objs):
        analyzer_objs = []
        for a_name, config in config_objs.items():
            analyzer_obj = Analyzer(
                name=a_name,
                analyzer_type=config.get("type", ""),
                disabled=config.get("disabled", False),
                description=config.get("description", ""),
                python_module=config.get("python_module", ""),
                supported_filetypes=config.get("supported_filetypes", []),
                not_supported_filetypes=config.get("not_supported_filetypes", []),
                run_hash=config.get("run_hash", False),
                run_hash_type=config.get("run_hash_type", ""),
                observable_supported=config.get("observable_supported", []),
                leaks_info=config.get("leaks_info", False),
                external_service=config.get("external_service", False),
                queue=config["config"].get("queue", "default"),
                soft_time_limit=config["config"].get("soft_time_limit", 300),
                additional_config_params=config.get("additional_config_params", {}),
            )
            analyzer_obj.save()
            secrets_dict = config.pop("secrets", {})
            Secret.objects.bulk_create(
                [
                    Secret(
                        name=f"{a_name}_{s_name}",
                        env_variable_key=s_config.get("secret_name", ""),
                        datatype=s_config.get("datatype", "str"),
                        default=s_config.get("default", None),
                        required=s_config.get("required", True),
                        description=s_config.get("description", ""),
                        analyzer=analyzer_obj,
                    )
                    for s_name, s_config in secrets_dict.items()
                ]
            )
            analyzer_objs.append(analyzer_obj)

        Analyzer.objects.bulk_create(analyzer_objs)

    def read_file(self, fpath):
        with open(fpath, "r") as fp:
            data = json.load(fp)

        return data
