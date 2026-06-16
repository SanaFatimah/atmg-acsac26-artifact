#!/bin/bash
# Build ATMG sandbox Docker images with pre-installed dependencies

set -e

echo "Building ATMG Python sandbox image..."
docker build -t atmg-python-sandbox:latest -f Dockerfile.python-sandbox .

echo ""
echo "✓ Build complete!"
echo ""
echo "Images built:"
docker images | grep atmg-python-sandbox

echo ""
echo "To use in sandbox.py, change line 8 to:"
echo '    "python": "atmg-python-sandbox:latest",'
