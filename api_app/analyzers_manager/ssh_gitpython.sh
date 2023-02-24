#!/bin/bash
ssh -i "/opt/deploy/files_required/my_gitpython_key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$@"