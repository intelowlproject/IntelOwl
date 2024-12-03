#!/bin/bash
service cron start
# Initial rules download
python yara_forge_analyzer.py --update-rules
# Keep container running
tail -f /dev/null