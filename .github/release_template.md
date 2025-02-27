# Checklist for creating a new release

- [ ] If we changed/added Docker Analyzers, we need to configure Docker Hub / Dependabot properly.
- [ ] I have already checked if all Dependabot issues have been solved before creating this PR.
- [ ] Update `CHANGELOG.md` for the new version. Tag another maintainer to review the Changelog and wait for their feedback.
- [ ] Change version number in `docker/.env` and `frontend/package.json`.
- [ ] Verify CI Tests. Solve all the issues (Dependencies, Django Doctor, CodeFactor, DeepSource, etc).
- [ ] Create release for the branch `develop` and set it as a `pre-release`. Remember to prepend a `v` to the version number.
      Write the following statement there (change the version number):

```commandline
please refer to the [Changelog](https://github.com/intelowlproject/IntelOwl/blob/develop/.github/CHANGELOG.md#v331)

WARNING: We are building the new version of the project! The release will be officially available within 2 hours!
```

- [ ] Wait for [dockerHub](https://hub.docker.com/repository/docker/intelowlproject/intelowl) to finish the builds
- [ ] Merge the PR to the `master` branch. **Note:** Only use "Merge and commit" as the merge strategy and not "Squash and merge". Using "Squash and merge" makes history between branches misaligned.
- [ ] Remove the "wait" statement in the release description and change the version status from `pre-release` to `latest release`.
- [ ] Publish new Post into official Twitter and LinkedIn accounts (change the version number):
```commandline
published #IntelOwl vX.X.X! https://github.com/intelowlproject/IntelOwl/releases/tag/vX.X.X #ThreatIntelligence #CyberSecurity #OpenSource #OSINT #DFIR
```
- [ ] If that was a major release or an important release, communicate the news to the marketing staff
- [ ] This is a good time to check for old dangling issues and clean-up the inactive ones. Same for issues solved by this release.