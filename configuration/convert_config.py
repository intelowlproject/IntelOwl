import json


def main():
    file_path = "analyzer_config.json"
    with open(file_path, "r") as f:
        config = json.load(f)

    new_config = {}
    for analyzer in config:
        new_config[analyzer] = {}
        new_config[analyzer]["type"] = config[analyzer]["type"]
        new_config[analyzer]["python_module"] = config[analyzer]["python_module"]

        if "requires_configuration" in config[analyzer]:
            new_config[analyzer]["requires_configuration"] = config[analyzer][
                "requires_configuration"
            ]

        if "leaks_info" in config[analyzer]:
            new_config[analyzer]["leaks_info"] = config[analyzer]["leaks_info"]

        if "run_hash" in config[analyzer]:
            new_config[analyzer]["run_hash"] = config[analyzer]["run_hash"]

        if "run_hash_type" in config[analyzer]:
            new_config[analyzer]["run_hash_type"] = config[analyzer]["run_hash_type"]

        if "disabled" in config[analyzer]:
            new_config[analyzer]["disabled"] = config[analyzer]["disabled"]

        if "external_service" in config[analyzer]:
            new_config[analyzer]["external_service"] = config[analyzer][
                "external_service"
            ]

        if "supported_filetypes" in config[analyzer]:
            new_config[analyzer]["supported_filetypes"] = config[analyzer][
                "supported_filetypes"
            ]

        if "not_supported_filetypes" in config[analyzer]:
            new_config[analyzer]["not_supported_filetypes"] = config[analyzer][
                "not_supported_filetypes"
            ]

        if "observable_supported" in config[analyzer]:
            new_config[analyzer]["observable_supported"] = config[analyzer][
                "observable_supported"
            ]

        if config[analyzer].get("description", None):
            new_config[analyzer]["description"] = config[analyzer]["description"]

        new_config[analyzer]["config"] = {}
        if config[analyzer].get("soft_time_limit", None):
            new_config[analyzer]["config"]["soft_time_limit"] = config[analyzer][
                "soft_time_limit"
            ]

        if config[analyzer].get("queue", None) or config[analyzer].get(
            "additional_config_params", {}
        ).get("queue", None):

            if config[analyzer]["queue"]:
                new_config[analyzer]["config"]["queue"] = config[analyzer]["queue"]
            else:
                new_config[analyzer]["config"]["queue"] = config[analyzer][
                    "additional_config_params"
                ]["queue"]

        new_config[analyzer]["secrets"] = {}
        if config[analyzer].get("additional_config_params", None) and config[analyzer][
            "additional_config_params"
        ].get("api_key_name", None):
            new_config[analyzer]["secrets"]["api_key"] = {
                "secret_name": config[analyzer]["additional_config_params"][
                    "api_key_name"
                ],
                "required": True,
                "default": None,
            }

        new_config[analyzer]["additional_config_params"] = config[analyzer].get(
            "additional_config_params", {}
        )

        if "api_key_name" in new_config[analyzer]["additional_config_params"]:
            # Secrets shouldn't be in additional_config_params
            # Some analyzers have multiple secrets. Do it manually.
            del new_config[analyzer]["additional_config_params"]["api_key_name"]

        if len(new_config[analyzer]["additional_config_params"].keys()) == 0:
            del new_config[analyzer]["additional_config_params"]

        if len(new_config[analyzer]["secrets"].keys()) == 0:
            del new_config[analyzer]["secrets"]

    with open("new_analyzer_config.json", "w") as f:
        json.dump(new_config, f, indent=4)


if __name__ == "__main__":
    main()
