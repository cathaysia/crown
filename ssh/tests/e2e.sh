#!/usr/bin/env bash
# End-to-end test for the crown libssh2 backend.
#
# Runs the crown-ssh client against a real OpenSSH server and walks the
# algorithm matrix: key exchange, host key type, cipher, MAC and
# authentication (password plus every key type crown can sign with). Every
# case performs a full handshake, an authenticated exec and checks the output.
#
# Usage: tests/e2e.sh [path-to-crown-ssh]
#
# Environment:
#   SSH_TEST_HOST      default 127.0.0.1
#   SSH_TEST_PORT      default 2222
#   SSH_TEST_USER      default crown
#   SSH_TEST_PASSWORD  default crown
#   SSH_TEST_WAIT     seconds to wait for the SSH banner (default 60)
#   SSH_TEST_CONTAINER optional: name of a running sshd container; when set,
#                      the generated public keys are installed into it
#
# SPDX-License-Identifier: BSD-3-Clause

set -u

CLIENT=${1:-"$(cd "$(dirname "$0")/.." && pwd)/build/crown-ssh"}
HOST=${SSH_TEST_HOST:-127.0.0.1}
PORT=${SSH_TEST_PORT:-2222}
USER=${SSH_TEST_USER:-crown}
PASS=${SSH_TEST_PASSWORD:-crown}
CONTAINER=${SSH_TEST_CONTAINER:-}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
failed_cases=""

run_case() {
    local name=$1
    shift
    local out
    out=$(printf '%s\n' "$PASS" | timeout 30 "$CLIENT" -p "$PORT" "$@" \
              "$USER@$HOST" 'echo E2E_OK' 2>&1)
    if [ $? -eq 0 ] && printf '%s' "$out" | grep -q E2E_OK; then
        printf 'ok   %s\n' "$name"
        pass=$((pass + 1))
    else
        printf 'FAIL %s\n' "$name"
        printf '%s\n' "$out" | sed 's/^/       /'
        fail=$((fail + 1))
        failed_cases="$failed_cases $name"
    fi
}

# ---------------------------------------------------------------------------
# Test keys (also exercise the OpenSSH key loader and the sign paths)
# ---------------------------------------------------------------------------

gen_key() {
    local type=$1
    local extra=${2:-}
    local path="$WORK/id_$type"
    ssh-keygen -q -t "$type" $extra -N '' -f "$path" -C "crown-e2e-$type" \
        </dev/null
    printf '%s' "$path"
}

KEY_ED25519=$(gen_key ed25519)
KEY_ECDSA256=$(gen_key ecdsa "-b 256")
KEY_ECDSA384=$(gen_key ecdsa "-b 384")
KEY_ECDSA521=$(gen_key ecdsa "-b 521")
KEY_RSA=$(gen_key rsa "-b 2048")

if [ -n "$CONTAINER" ]; then
    cat "$WORK"/id_*.pub | docker exec -i "$CONTAINER" sh -c \
        "mkdir -p /home/$USER/.ssh && cat >> /home/$USER/.ssh/authorized_keys && chown -R $USER /home/$USER/.ssh && chmod 600 /home/$USER/.ssh/authorized_keys"
    echo "# installed test public keys into container $CONTAINER"
fi

# The TCP port can be open (docker-proxy) well before sshd has finished
# generating its host keys, so wait for the actual SSH banner.
wait_for_sshd() {
    local wait=${SSH_TEST_WAIT:-60}
    local deadline=$((SECONDS + wait))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if timeout 3 bash -c "exec 3<>/dev/tcp/$HOST/$PORT; head -c 4 <&3" \
                2>/dev/null | grep -q 'SSH-'; then
            return 0
        fi
        sleep 1
    done
    echo "crown-ssh: no SSH banner on $HOST:$PORT within ${wait}s" >&2
    return 1
}

wait_for_sshd || exit 1

echo "# crown-ssh: $CLIENT"
"$CLIENT" -v -p "$PORT" "$USER@$HOST" true 2>&1 | grep -E "libssh2|crypto backend" \
    | sed 's/^/# /'

# ---------------------------------------------------------------------------
# Matrix
# ---------------------------------------------------------------------------

for c in chacha20-poly1305@openssh.com aes128-ctr aes192-ctr aes256-ctr \
         aes128-cbc aes192-cbc aes256-cbc; do
    run_case "cipher $c" -c "$c"
done

for m in hmac-sha2-256 hmac-sha2-512 hmac-sha1; do
    run_case "mac $m" -m "$m" -c aes128-ctr
done

for k in curve25519-sha256 curve25519-sha256@libssh.org \
         ecdh-sha2-nistp256 ecdh-sha2-nistp384 ecdh-sha2-nistp521 \
         diffie-hellman-group14-sha256 diffie-hellman-group16-sha512 \
         diffie-hellman-group18-sha512 \
         diffie-hellman-group-exchange-sha256; do
    run_case "kex $k" -k "$k"
done

for h in ssh-ed25519 ecdsa-sha2-nistp256 ecdsa-sha2-nistp384 \
         ecdsa-sha2-nistp521 rsa-sha2-512 rsa-sha2-256; do
    run_case "hostkey $h" -H "$h"
done

run_case "auth password"

for k in "$KEY_ED25519" "$KEY_ECDSA256" "$KEY_ECDSA384" "$KEY_ECDSA521" \
         "$KEY_RSA"; do
    run_case "auth publickey $(basename "$k")" -i "$k"
done

echo
echo "# $pass passed, $fail failed"
[ "$fail" -eq 0 ] || {
    echo "# failed:$failed_cases"
    exit 1
}
