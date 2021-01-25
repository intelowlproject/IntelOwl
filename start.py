import subprocess
import argparse

docker_analyzers = ["thug", "apk_analyzers", "box_js", "static_analyzers", "qiling"]

path_mapping = {
    "default": "docker/default.yml",
    "test": "docker/test.override.yml",
    "ci": "docker/ci.override.yml",
    "custom": "docker/custom.override.yml",
    "traefik": "docker/traefik.override.yml",
    "multi_queue": "docker/multi-queue.override.yml",
}
path_mapping.update(
    {name: f"integrations/{name}/compose.yml" for name in docker_analyzers}
)
path_mapping.update(
    {
        name + ".test": f"integrations/{name}/compose-tests.yml"
        for name in docker_analyzers
    }
)
path_mapping["all_analyzers"] = [path_mapping[key] for key in docker_analyzers]
path_mapping["all_analyzers.test"] = [
    path_mapping[key + ".test"] for key in docker_analyzers
]


def start():
    parser = argparse.ArgumentParser()
    # mandatory arguments
    parser.add_argument("mode", type=str, choices=["prod", "test", "ci"])
    parser.add_argument(
        "docker_command",
        type=str,
        choices=[
            "build",
            "up",
            "start",
            "restart",
            "down",
            "stop",
            "kill",
            "logs",
            "ps",
        ],
    )

    # integrations
    parser.add_argument(
        "--all_analyzers",
        required=False,
        action="store_true",
        help="Uses every integration",
    )
    for integration in docker_analyzers:
        parser.add_argument(
            f"--{integration}",
            required=False,
            action="store_true",
            help=f"Uses the integrations/{integration}/compose.yml file",
        )

    # possible upgrades
    parser.add_argument(
        "--multi_queue",
        required=False,
        action="store_true",
        help="Uses the multiqueue.override.yml compose file",
    )
    parser.add_argument(
        "--traefik",
        required=False,
        action="store_true",
        help="Uses the traefik.override.yml compose file",
    )
    parser.add_argument(
        "--custom",
        required=False,
        action="store_true",
        help="Uses custom.override.yml to leverage your customized configuration",
    )
    args, unknown = parser.parse_known_args()
    # logic
    test_appendix = ""
    if args.mode == "test":
        test_appendix = ".test"
    docker_flags = [
        args.__dict__[docker_analyzer] for docker_analyzer in docker_analyzers
    ]
    if args.all_analyzers and any(docker_flags):
        parser.error(
            "It is not possible to select both  "
            "`all_analyzers` and another docker container"
        )
        return
    # default file
    compose_files = [path_mapping["default"]]
    # mode
    if args.mode in ["ci", "test"]:
        compose_files.append(path_mapping[args.mode])
    # upgrades
    for key in ["traefik", "multi_queue", "custom"]:
        if args.__dict__[key]:
            compose_files.append(path_mapping[key])
    # additional integrations
    for key in docker_analyzers:
        if args.__dict__[key]:
            compose_files.append(path_mapping[key + test_appendix])
    if args.all_analyzers:
        compose_files.extend(
            [analyzer for analyzer in path_mapping[f"all_analyzers{test_appendix}"]]
        )
    # construct final command
    base_command = ["docker-compose", "-p", "intel_owl"]
    for compose_file in compose_files:
        base_command.append("-f")
        base_command.append(compose_file)
    # we use try/catch to mimick docker-compose's behaviour of handling CTRL+C event
    try:
        command = base_command + [args.docker_command] + unknown
        subprocess.run(command)
    except KeyboardInterrupt:
        print(
            "---- removing the containers, please wait... ",
            "(press Ctrl+C again to force) ----",
        )
        try:
            subprocess.run(base_command + ["down"])
        except KeyboardInterrupt:
            # just need to catch it
            pass


if __name__ == "__main__":
    start()
