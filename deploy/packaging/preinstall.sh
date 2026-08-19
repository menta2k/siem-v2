#!/bin/sh
# The units run as an unprivileged service user; create it if absent.
set -e
if ! getent passwd siem >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin siem
fi
