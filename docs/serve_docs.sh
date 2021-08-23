#!/usr/bin/env bash
export DJANGO_SETTINGS_MODULE="intel_owl.settings"
make html
cd build/html && python3 -m http.server 6969 && cd ../../