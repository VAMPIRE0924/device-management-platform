#!/bin/sh
set -eu

data_dir="${DMP_DATA_DIR:-/data}"

if [ "$(id -u)" -eq 0 ]; then
    mkdir -p "$data_dir"

    # Bind-mounted NAS directories keep their host ownership instead of the
    # ownership baked into the image. Fix only the dedicated data directory,
    # then run the application as the unprivileged platform user.
    chown -R platform:platform "$data_dir" 2>/dev/null || true

    if ! su-exec platform test -w "$data_dir"; then
        echo "fatal: $data_dir is not writable by the platform user; check the host directory permissions" >&2
        exit 1
    fi

    exec su-exec platform /usr/local/bin/device-management-platform "$@"
fi

exec /usr/local/bin/device-management-platform "$@"
