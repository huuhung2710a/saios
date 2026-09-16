#!/bin/bash
set -e

APP_NAME="HuuHungSAMP"

echo "=== Creating $APP_NAME iOS project ==="

mkdir -p ios

cat > ios/README.md <<'EOF'
# HuuHungSAMP iOS

iOS SA-MP client/launcher project.

Target:
- GTA San Andreas Classic iOS 2.2.21
- SA-MP compatible client
- GitHub Actions macOS/Xcode build
EOF

echo "iOS project directory created."
echo "Next step: generate the Xcode project."
