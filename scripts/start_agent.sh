#!/bin/bash

export RUST_LOG=keylime_agent=debug,keylime=debug
export KEYLIME_AGENT_IP=0.0.0.0
export KEYLIME_AGENT_RUN_AS=""
export KEYLIME_AGENT_REGISTRAR_IP=192.168.122.1
export KEYLIME_AGENT_CONTACT_IP="$(hostname -I | awk '{print $1}')"

GIT_ROOT=$(git rev-parse --show-toplevel)
if [[ $? -ne 0 ]]; then
    echo "Please run this script from inside the rust-keylime repository tree"
fi

pushd ${GIT_ROOT} > /dev/null
    cargo build
popd

sudo mkdir -p /var/lib/keylime

${GIT_ROOT}/target/debug/keylime_agent

