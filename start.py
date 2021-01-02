import subprocess
import argparse

docker_analyzers = ["thug", "apk_analyzers", "box_js", "static_analyzers", "qiling"]

path_mapping = {
    "default": "docker/default.yml",
    "test": "docker/test.override.yml",
    "ci": "docker/ci.override.yml",
    "traefik": "docker/traefik.override.yml",
    "multi_queue": "docker/multi-queue.override.yml",
    "apk_analyzers": "integrations/apk_analyzers/apk.yml",
    "box_js": "integrations/box-js/boxjs.yml",
    "static_analyzers": "integrations/static_analyzers/static_analyzers.yml",
    "thug": "integrations/thug/thug.yml",
    "apk_analyzers.test": "integrations/apk_analyzers/apk.test.yml",
    "box_js.test": "integrations/box-js/boxjs.test.yml",
    "static_analyzers.test": "integrations/static_analyzers/static_analyzers.test.yml",
    "thug.test": "integrations/thug/thug.test.yml",
    "qiling": "integrations/qiling/qiling.yml",
    "qiling.test": "integrations/qiling/qiling.test.yml",
}
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
            "--" + integration,
            required=False,
            action="store_true",
            help="Uses the integration/" + integration + ".yml compose file",
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
    compose_files = []
    compose_files.append(path_mapping["default"])
    if args.mode in ["ci", "test"]:
        compose_files.append(path_mapping[args.mode])
    for key in ["traefik", "multi_queue"]:
        if args.__dict__[key]:
            compose_files.append(path_mapping[key])
    for key in docker_analyzers:
        if args.__dict__[key]:
            compose_files.append(path_mapping[key + test_appendix])
    if args.all_analyzers:
        compose_files.extend(
            [analyzer for analyzer in path_mapping["all_analyzers" + test_appendix]]
        )
    # construct final command
    base_command = [
        "docker-compose",
        "-p",
        "intel_owl",
        "-f",
        "-f ".join(compose_files),
    ]
    # we use try/catch to mimick docker-compose's behaviour of handling CTRL+C event
    try:
        subprocess.run(base_command + [args.docker_command] + unknown)
    except KeyboardInterrupt:
        print(
            "---- stopping the containers, please wait... ",
            "(press Ctrl+C again to force) ----",
        )
        try:
            subprocess.run(base_command + ["stop"])
        except KeyboardInterrupt:
            # just need to catch it
            pass


if __name__ == "__main__":
    start()
