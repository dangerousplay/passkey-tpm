#!/usr/bin/env bash
# Renders the documentation figures with spinagram (https://github.com/dangerousplay/spinagram):
#   uv tool install "spinagram[all]"
# Wide architecture views use theme-wide/, the swimlane flows theme/.
set -euo pipefail
cd "$(dirname "$0")"
spinagram check src/d01_architecture.py src/d04_tpm_policy.py -t theme-wide
spinagram check src/d02_fingerprint_flow.py src/d03_pin_presence_flow.py -t theme
spinagram render src/d01_architecture.py src/d04_tpm_policy.py -t theme-wide -f svg -o . --no-gallery
spinagram render src/d02_fingerprint_flow.py src/d03_pin_presence_flow.py -t theme -f svg -o . --no-gallery
