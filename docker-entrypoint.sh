#!/bin/sh
set -eu

data_dir="${DMP_DATA_DIR:-/data}"

config_value() {
    setting_name=$1
    shift
    for config_path in "$@"; do
        [ -r "$config_path" ] || continue
        configured=$(awk -v wanted="$setting_name" '
            /^[[:space:]]*[#;]/ { next }
            {
                separator = index($0, "=")
                if (separator == 0) next
                key = substr($0, 1, separator - 1)
                value = substr($0, separator + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                if (key == wanted && value != "") found = value
            }
            END { if (found != "") print found }
        ' "$config_path")
        if [ -n "$configured" ]; then
            printf '%s' "$configured"
            return 0
        fi
    done
    return 1
}

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

    base_config_file="${DMP_CONFIG_FILE:-/etc/device-management-platform/platform.conf}"
    override_file="${DMP_SETTINGS_OVERRIDE_FILE:-}"
    if [ -z "$override_file" ]; then
        override_file=$(config_value settings_override_file "$base_config_file" 2>/dev/null || true)
    fi
    override_file="${override_file:-$data_dir/settings.override.conf}"

    tls_cert_file="${DMP_TLS_CERT_FILE:-}"
    tls_key_file="${DMP_TLS_KEY_FILE:-}"
    if [ -z "$tls_cert_file" ]; then
        tls_cert_file=$(config_value tls_cert_file "$override_file" "$base_config_file" 2>/dev/null || true)
    fi
    if [ -z "$tls_key_file" ]; then
        tls_key_file=$(config_value tls_key_file "$override_file" "$base_config_file" 2>/dev/null || true)
    fi

    access_tls_cert_file="${DMP_ACCESS_TLS_CERT_FILE:-}"
    access_tls_key_file="${DMP_ACCESS_TLS_KEY_FILE:-}"
    if [ -z "$access_tls_cert_file" ]; then
        access_tls_cert_file=$(config_value access_tls_cert_file "$override_file" "$base_config_file" 2>/dev/null || true)
    fi
    if [ -z "$access_tls_key_file" ]; then
        access_tls_key_file=$(config_value access_tls_key_file "$override_file" "$base_config_file" 2>/dev/null || true)
    fi

    if [ -n "$tls_cert_file" ] || [ -n "$tls_key_file" ]; then
        if [ -z "$tls_cert_file" ] || [ -z "$tls_key_file" ]; then
            echo "fatal: both TLS certificate and private key paths must be configured" >&2
            exit 1
        fi
        if ! su-exec platform test -r "$tls_cert_file" || ! su-exec platform test -r "$tls_key_file"; then
            if [ ! -r "$tls_cert_file" ] || [ ! -r "$tls_key_file" ]; then
                echo "fatal: mounted TLS certificate or private key is not readable by the container root user" >&2
                exit 1
            fi
            # The NAS certificate mount remains read-only. Open read-only file
            # descriptors before dropping privileges; never copy or modify it.
            exec 3<"$tls_cert_file"
            exec 4<"$tls_key_file"
            export DMP_RUNTIME_TLS_CERT_FD=3
            export DMP_RUNTIME_TLS_KEY_FD=4
            export DMP_RUNTIME_TLS_CERT_PATH="$tls_cert_file"
            export DMP_RUNTIME_TLS_KEY_PATH="$tls_key_file"
        fi
    fi

    if [ -n "$access_tls_cert_file" ] || [ -n "$access_tls_key_file" ]; then
        if [ -z "$access_tls_cert_file" ] || [ -z "$access_tls_key_file" ]; then
            echo "fatal: both access TLS certificate and private key paths must be configured" >&2
            exit 1
        fi
        if ! su-exec platform test -r "$access_tls_cert_file" || ! su-exec platform test -r "$access_tls_key_file"; then
            if [ ! -r "$access_tls_cert_file" ] || [ ! -r "$access_tls_key_file" ]; then
                echo "fatal: mounted access TLS certificate or private key is not readable by the container root user" >&2
                exit 1
            fi
            exec 5<"$access_tls_cert_file"
            exec 6<"$access_tls_key_file"
            export DMP_RUNTIME_ACCESS_TLS_CERT_FD=5
            export DMP_RUNTIME_ACCESS_TLS_KEY_FD=6
            export DMP_RUNTIME_ACCESS_TLS_CERT_PATH="$access_tls_cert_file"
            export DMP_RUNTIME_ACCESS_TLS_KEY_PATH="$access_tls_key_file"
        fi
    fi

    exec su-exec platform /usr/local/bin/device-management-platform "$@"
fi

exec /usr/local/bin/device-management-platform "$@"
