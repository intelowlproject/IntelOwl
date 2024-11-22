# Checklist for creating a new release

- [ ] If we changed/added Docker Analyzers, we need to configure Docker Hub / Dependabot properly.
- [ ] I have already checked if all Dependabot issues have been solved before creating this PR.
- [ ] Update `CHANGELOG.md` for the new version. Tag another maintainer to review the Changelog and wait for their feedback.
- [ ] Change version number `docker/.env`
- [ ] Verify CI Tests
- [ ] Create release for the branch `develop`. Remember to prepend a `v` to the version number.
      Write the following statement there (change the version number):

```commandline
please refer to the [Changelog](https://github.com/intelowlproject/IntelOwl/blob/develop/.github/CHANGELOG.md#v331)

WARNING: The release will be live within an hour!
```

- [ ] Wait for [dockerHub](https://hub.docker.com/repository/docker/intelowlproject/intelowl) to finish the builds
- [ ] Merge the PR to the `master` branch. **Note:** Only use "Merge and commit" as the merge strategy and not "Squash and merge". Using "Squash and merge" makes history between branches misaligned.
- [ ] Remove the "wait" statement in the release description.
- [ ] Publish new Post into official Twitter and LinkedIn accounts (change the version number):
```commandline
published #IntelOwl vX.X.X! https://github.com/intelowlproject/IntelOwl/releases/tag/vX.X.X #ThreatIntelligence #CyberSecurity #OpenSource #OSINT #DFIR
```
- [ ] If that was a major release or an important release, communicate the news to the marketing staff