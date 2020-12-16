import click
import subprocess

INTELOWL_TAG_VERSION = "v1.9.1"

docker_analyzers = ["thug", "apk_analyzers", "box_js", "static_analyzers"]

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
}
path_mapping["all_analyzers"] = [path_mapping[key] for key in docker_analyzers]
path_mapping["all_analyzers.test"] = [
    path_mapping[f"{key}.test"] for key in docker_analyzers
]


@click.command(
    context_settings=dict(
        ignore_unknown_options=True,
        allow_extra_args=True,
    )
)
@click.argument("mode", required=True, type=click.Choice(["prod", "test", "ci"]))
@click.argument(
    "docker_command", required=True, type=click.Choice(["build", "up", "down"])
)
@click.option(
    "--traefik",
    default=False,
    is_flag=True,
    help="Uses the traefik.override.yml compose file",
)
@click.option(
    "--multi_queue",
    default=False,
    is_flag=True,
    help="Uses the multiqueue.override.yml compose file",
)
@click.option(
    "--thug",
    default=False,
    is_flag=True,
    help="Uses the integration/thug.override.yml compose file",
)
@click.option(
    "--static_analyzers",
    default=False,
    is_flag=True,
    help="Uses the integration/static-analyzers.override.yml compose file",
)
@click.option(
    "--box_js",
    default=False,
    is_flag=True,
    help="Uses the integration/box-js.override.yml compose file",
)
@click.option(
    "--apk_analyzers",
    default=False,
    is_flag=True,
    help="Uses the integration/apk-analyzers.override.yml compose file",
)
@click.option(
    "--all_analyzers", default=False, is_flag=True, help="Uses every integration"
)
@click.pass_context
def start(
    ctx,
    mode,
    docker_command,
    traefik,
    thug,
    static_analyzers,
    box_js,
    apk_analyzers,
    all_analyzers,
    multi_queue,
):
    local_keys = locals()
    test_appendix = ""
    if mode == "test":
        test_appendix = ".test"
    docker_flags = [local_keys[docker_analyzer] for docker_analyzer in docker_analyzers]
    if all_analyzers and any(docker_flags):
        click.echo(
            "It is not possible to select both  "
            "`all_analyzers` and another docker container"
        )
        return
    command = "docker-compose"
    command += f" -f {path_mapping['default']}"
    if mode in ["ci", "test"]:
        command += f" -f {path_mapping[mode]}"
    for key in ["traefik", "multi_queue"]:
        if key in local_keys and local_keys[key]:
            command += f" -f {path_mapping[key]}"
    for key in docker_analyzers:
        if key in local_keys and local_keys[key]:
            command += f" -f {path_mapping[f'{key}{test_appendix}']}"
    if all_analyzers:
        command += "".join(
            [
                " -f " + analyzer
                for analyzer in path_mapping[f"all_analyzers{test_appendix}"]
            ]
        )

    command += f" {docker_command}"

    subprocess.run(command.split(" ") + ctx.args, check=True)


if __name__ == "__main__":
    start()
