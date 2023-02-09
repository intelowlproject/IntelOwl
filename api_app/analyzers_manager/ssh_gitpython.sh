#!/bin/bash
ssh -i "/run/secrets/my_gitpython_key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$@"