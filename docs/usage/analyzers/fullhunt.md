# 1. Ensure the directory exists
New-Item -ItemType Directory -Force -Path "docs/usage/analyzers"

# 2. Create the file with the content
$mdContent = @"
# FullHunt

[FullHunt](https://fullhunt.io/) is a comprehensive attack surface management platform. This analyzer allows IntelOwl to query FullHunt for intelligence regarding domains and subdomains.

## Credentials
- ``api_key``: A valid API key from FullHunt.

## Parameters
- ``url``: The API endpoint. Default: ``https://fullhunt.io/api/v1``

## Supported Observables
- ``domain``
"@

Set-Content -Path "docs/usage/analyzers/fullhunt.md" -Value $mdContent