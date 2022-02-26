# Checklist for creating a new release

- [ ] (optional) If we changed/added Docker Analyzers, we need to configure Docker Hub properly.
- [ ] Update `CHANGELOG.md` for the new version
- [ ] Change version number in `conf.py`, `.env`,  `settings.SPECTACULAR_SETTINGS`, `Dockerfile_nginx` and `schema.yml`
- [ ] Verify CI Tests
- [ ] Create release for the branch `develop`
- [ ] Wait for dockerHub to finish the builds
- [ ] Merge the PR to the `master` branch

**Note:** Only use "Merge and commit" as the merge strategy and not "Squash and merge". Using "Squash and merge" makes history between branches misaligned.

