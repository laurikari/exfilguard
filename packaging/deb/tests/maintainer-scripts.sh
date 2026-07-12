#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

mkdir -p "$tmp/bin" "$tmp/systemd"

sed "s|/run/systemd/system|$tmp/systemd|g" \
    "$repo_root/packaging/deb/scripts/prerm" >"$tmp/prerm"
sed "s|/run/systemd/system|$tmp/systemd|g" \
    "$repo_root/packaging/deb/scripts/postinst" >"$tmp/postinst"
sed "s|/run/systemd/system|$tmp/systemd|g" \
    "$repo_root/packaging/deb/scripts/postrm" >"$tmp/postrm"
chmod +x "$tmp/prerm" "$tmp/postinst" "$tmp/postrm"

for command in dpkg systemctl deb-systemd-invoke systemd-sysusers systemd-tmpfiles; do
    ln -s command-stub "$tmp/bin/$command"
done

cat >"$tmp/bin/command-stub" <<'EOF'
#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >>"$COMMAND_LOG"

if [ "${0##*/}" = "dpkg" ] && [ "$1" = "--compare-versions" ]; then
    case "$2" in
        0.[0-8]|0.[0-8].*) exit 0 ;;
        *) exit 1 ;;
    esac
fi

if [ "${0##*/}" = "systemctl" ] && [ "$*" = "--system is-enabled --quiet exfilguard.service" ]; then
    [ "${UNIT_ENABLED:-yes}" = "yes" ]
    exit
fi

exit 0
EOF
chmod +x "$tmp/bin/command-stub"

run_script() {
    : >"$tmp/commands"
    COMMAND_LOG="$tmp/commands" PATH="$tmp/bin:$PATH" \
        UNIT_ENABLED="${UNIT_ENABLED:-yes}" "$@"
}

assert_line() {
    if ! grep -Fx "$1" "$tmp/commands" >/dev/null; then
        printf 'missing command: %s\n' "$1" >&2
        cat "$tmp/commands" >&2
        exit 1
    fi
}

assert_no_service_action() {
    if grep -E '^(deb-systemd-invoke|systemctl .* (start|stop|restart|try-restart))' \
        "$tmp/commands" >/dev/null; then
        printf 'unexpected service action:\n' >&2
        cat "$tmp/commands" >&2
        exit 1
    fi
}

assert_no_host_systemd_command() {
    if grep -E '^(deb-systemd-invoke|systemctl)' "$tmp/commands" >/dev/null; then
        printf 'alternate-root operation controlled host systemd:\n' >&2
        cat "$tmp/commands" >&2
        exit 1
    fi
}

run_script "$tmp/prerm" upgrade 0.9.0
assert_no_service_action

run_script "$tmp/prerm" remove
assert_line "deb-systemd-invoke stop exfilguard.service"

run_script "$tmp/postinst" configure
assert_line "systemd-sysusers exfilguard.conf"
assert_line "systemd-tmpfiles --create exfilguard.conf"
assert_line "systemctl --system daemon-reload"
assert_no_service_action

run_script "$tmp/postinst" configure 0.8.1
assert_line "systemctl --system daemon-reload"
assert_line "systemctl --system is-enabled --quiet exfilguard.service"
assert_line "deb-systemd-invoke start exfilguard.service"

UNIT_ENABLED=no run_script "$tmp/postinst" configure 0.8.1
assert_line "deb-systemd-invoke try-restart exfilguard.service"

run_script "$tmp/postinst" configure 0.9.0
assert_line "systemctl --system daemon-reload"
assert_line "deb-systemd-invoke try-restart exfilguard.service"

: >"$tmp/commands"
COMMAND_LOG="$tmp/commands" PATH="$tmp/bin:$PATH" DPKG_ROOT="$tmp/root" \
    "$tmp/postinst" configure 0.8.1
assert_line "systemd-sysusers --root=$tmp/root exfilguard.conf"
assert_line "systemd-tmpfiles --root=$tmp/root --create exfilguard.conf"
assert_no_host_systemd_command

touch "$tmp/systemd/present"
run_script "$tmp/postrm" remove
assert_line "systemctl --system daemon-reload"
assert_line "systemctl --system reset-failed exfilguard.service"

mkdir -p "$tmp/root/var/lib/exfilguard"
touch "$tmp/root/var/lib/exfilguard/sentinel"
: >"$tmp/commands"
COMMAND_LOG="$tmp/commands" PATH="$tmp/bin:$PATH" DPKG_ROOT="$tmp/root" \
    "$tmp/postrm" purge
if [ -e "$tmp/root/var/lib/exfilguard" ]; then
    printf 'alternate-root purge retained target state\n' >&2
    exit 1
fi
assert_no_host_systemd_command
