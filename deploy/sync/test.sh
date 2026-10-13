#!/bin/sh
# End-to-end test of sync (docs/adr/0002) with Docker: an origin and a replica.
#
#   ./deploy/sync/test.sh
#
# Checks that the replica takes the origin's settings, picks up a change after
# the origin reloads, and still answers from its state file when it restarts
# while the origin is down. Needs docker (with compose) and dig.
set -eu
cd "$(dirname "$0")"

work=$(mktemp -d)
compose() { docker compose -p zinkhole-sync-test -f docker-compose.yml "$@"; }
cleanup() {
    compose down -v >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

# The test edits a copy of the origin's config.
cp origin.yaml "$work/origin.yaml"
export ZINKHOLE_ORIGIN_CONFIG="$work/origin.yaml"

# Waits until `dig` on the replica returns `want` for `name`.
expect() {
    name=$1 want=$2 what=$3
    for _ in $(seq 30); do
        got=$(dig @127.0.0.1 -p 5302 +short +tries=1 +time=1 "$name" A || true)
        if [ "$got" = "$want" ]; then
            echo "ok: $what"
            return 0
        fi
        sleep 1
    done
    echo "FAIL: $what: $name is '$got', expected '$want'" >&2
    compose logs >&2
    exit 1
}

compose up -d --build
expect nas.lan 192.168.1.10 "the replica answers with the origin's local record"
expect ads.example 0.0.0.0 "the replica blocks what the origin blocks"

# Rewrite the file in place: the bind mount follows the inode, not the name.
sed 's/192.168.1.10/192.168.1.11/' "$work/origin.yaml" > "$work/origin.new"
cat "$work/origin.new" > "$work/origin.yaml"
compose kill -s HUP origin
expect nas.lan 192.168.1.11 "a reloaded change on the origin reaches the replica"

compose stop origin
compose restart replica
expect nas.lan 192.168.1.11 "a restarted replica answers from its state file while the origin is down"

echo "PASS"
