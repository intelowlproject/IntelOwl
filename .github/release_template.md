# Checklist for creating a new release

- [ ] (optional) If we changed/added Docker Analyzers, we need to configure Docker Hub / Dependabot properly.
- [ ] Update `CHANGELOG.md` for the new version
- [ ] Change version number in `docs/source/conf.py`, `docs/schema.yml`, `docker/.env`, `docker/.version`, `settings.commons.py` and `start.py`
- [ ] Verify CI Tests
- [ ] Create release for the branch `develop`. [Automate.io](https://automate.io/app/bots/list) should automatically create [Twitter](https://twitter.com/intel_owl) and [Linkedin](https://www.linkedin.com/in/matteo-lodi-90/) posts.
      Write the following statement there (change the version number):

```commandline
please refer to the [Changelog](https://github.com/intelowlproject/IntelOwl/blob/develop/.github/CHANGELOG.md#v331)

WARNING: The release will be live within an hour!
```

- [ ] Wait for [dockerHub](https://hub.docker.com/repository/docker/intelowlproject/intelowl) to finish the builds
- [ ] Merge the PR to the `master` branch. **Note:** Only use "Merge and commit" as the merge strategy and not "Squash and merge". Using "Squash and merge" makes history between branches misaligned.
- [ ] Remove the "wait" statement in the release description.
- [ ] If the analyzer is free, Please add it in the `FREE_TO_USE_ANALYZERS` playbook in `playbook_config.json`
