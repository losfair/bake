#!/bin/bash

set -e

cd "$(dirname $0)/.."
if [ -f "$HOME/proxy.sh" ]; then
  . "$HOME/proxy.sh"
  echo "Loaded proxy configuration"
fi

docker build -t bake --ulimit=nofile=100000:100000 --build-arg http_proxy --build-arg https_proxy .
