#!/bin/sh
# Release steps for GitLab CI (see .gitlab-ci.yml and docs/adr/0003). Run from
# the repository root; every step also works locally.
#
#   deploy/ci/release.sh version            print the version from build.zig.zon
#   deploy/ci/release.sh check-tag TAG      fail unless TAG is v<that version>
#   deploy/ci/release.sh build              build dist/: binaries, scripts, SHA256SUMS
#   deploy/ci/release.sh publish [--dry-run]  upload dist/ and create the release
#
# publish needs CI_JOB_TOKEN, CI_API_V4_URL, CI_PROJECT_ID and CI_COMMIT_TAG.
set -eu

targets="x86_64-linux-musl aarch64-linux-musl"
dist=dist

die() {
	echo "error: $*" >&2
	exit 1
}

version() {
	v=$(sed -n 's/^[[:space:]]*\.version[[:space:]]*=[[:space:]]*"\([0-9][0-9.]*\)".*/\1/p' build.zig.zon)
	[ -n "$v" ] || die "cannot read .version from build.zig.zon"
	echo "$v"
}

check_tag() {
	[ $# -eq 1 ] || die "usage: release.sh check-tag TAG"
	want="v$(version)"
	[ "$1" = "$want" ] || die "tag $1 does not match build.zig.zon: expected $want (bump .version, commit, and tag again)"
	echo "tag $1 matches build.zig.zon"
}

build() {
	rm -rf "$dist"
	mkdir -p "$dist"
	for target in $targets; do
		zig build --release -Dstrip=true -Dtarget="$target" --prefix "$dist/$target"
		install -m 755 "$dist/$target/bin/zinkhole" "$dist/zinkhole-$target"
		rm -rf "${dist:?}/$target"
	done
	# The Proxmox scripts (ADR-0003) travel with the release they belong to. The
	# entry scripts learn their version (the BASE_URL line), so that they fetch
	# lib.sh and everything else from this release and not a newer one.
	for script in deploy/proxmox/*.sh; do
		[ -e "$script" ] || continue
		sed "/^BASE_URL=/s/@VERSION@/$(version)/" "$script" >"$dist/$(basename "$script")"
		chmod 755 "$dist/$(basename "$script")"
	done
	# MIT asks for the notice to accompany copies of the software.
	install -m 644 LICENSE "$dist/LICENSE"
	# What deploy/install.sh needs next to it. The Proxmox installer and `update`
	# use it instead of GitLab's source archive, which has no checksum we control.
	tar -czf "$dist/zinkhole-deploy.tar.gz" deploy/install.sh deploy/zinkhole.service deploy/openrc/zinkhole config.example.yaml
	(cd "$dist" && sha256sum -- * >SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS)
	echo "built $(version):"
	(cd "$dist" && ls -l)
}

publish() {
	dry=no
	[ "${1:-}" = "--dry-run" ] && dry=yes
	[ -d "$dist" ] && [ -e "$dist/SHA256SUMS" ] || die "run 'build' first"
	: "${CI_API_V4_URL:?}" "${CI_PROJECT_ID:?}" "${CI_COMMIT_TAG:?}"
	check_tag "$CI_COMMIT_TAG"
	v=$(version)
	package="$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/zinkhole/$v"

	links='[]'
	for file in "$dist"/*; do
		name=$(basename "$file")
		if [ "$dry" = yes ]; then
			echo "would upload $name to $package/$name"
		else
			curl -fsS --header "JOB-TOKEN: ${CI_JOB_TOKEN:?}" --upload-file "$file" "$package/$name" >/dev/null
		fi
		# direct_asset_path makes .../releases/permalink/latest/downloads/<name> work.
		links=$(echo "$links" | jq -c --arg name "$name" --arg url "$package/$name" \
			'. + [{name: $name, url: $url, direct_asset_path: ("/" + $name), link_type: "package"}]')
	done

	body=$(jq -n -c --arg tag "$CI_COMMIT_TAG" --arg v "$v" --argjson links "$links" '{
		name: $tag,
		tag_name: $tag,
		description: ("zinkhole " + $v + "\n\nVerify downloads with SHA256SUMS."),
		assets: {links: $links}
	}')
	if [ "$dry" = yes ]; then
		echo "$body" | jq .
		return 0
	fi
	curl -fsS --header "JOB-TOKEN: ${CI_JOB_TOKEN:?}" --header "Content-Type: application/json" \
		--data "$body" "$CI_API_V4_URL/projects/$CI_PROJECT_ID/releases" >/dev/null
	echo "released $CI_COMMIT_TAG"
}

[ $# -ge 1 ] || die "usage: release.sh version|check-tag|build|publish"
cmd=$1
shift
case "$cmd" in
version) version ;;
check-tag) check_tag "$@" ;;
build) build ;;
publish) publish "$@" ;;
*) die "unknown command '$cmd'" ;;
esac
