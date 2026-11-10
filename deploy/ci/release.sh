#!/bin/sh
# Release steps for GitHub Actions (see .github/workflows/ci.yml and
# docs/adr/0001). Run from the repository root; every step also works locally.
#
#   deploy/ci/release.sh version            print the version from Cargo.toml
#   deploy/ci/release.sh check-tag TAG      fail unless TAG is v<that version>
#   deploy/ci/release.sh binary ARCH        build dist/zinkhole-ARCH-linux-musl
#                                           (x86_64 or aarch64, on that machine)
#   deploy/ci/release.sh image-layout       put the binaries where the image
#                                           build takes them (BINARY=dist)
#   deploy/ci/release.sh bundle             add the scripts, the deploy bundle,
#                                           LICENSE and SHA256SUMS to dist/
#   deploy/ci/release.sh publish [--dry-run]  upload dist/ and create the release
#
# publish needs the gh CLI, GH_TOKEN and GITHUB_REF_NAME (the tag).
set -eu

dist=dist

die() {
	echo "error: $*" >&2
	exit 1
}

# The package version: the first `version =` line, which is [package]'s.
version() {
	v=$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([0-9][0-9A-Za-z.+-]*\)".*/\1/p' Cargo.toml | head -n 1)
	[ -n "$v" ] || die "cannot read the version from Cargo.toml"
	echo "$v"
}

check_tag() {
	[ $# -eq 1 ] || die "usage: release.sh check-tag TAG"
	want="v$(version)"
	[ "$1" = "$want" ] || die "tag $1 does not match Cargo.toml: expected $want (bump the version, commit, and tag again)"
	echo "tag $1 matches Cargo.toml"
}

# A static musl binary for ARCH. Built on a machine of that architecture, so
# ring's C parts need only musl-gcc (musl-tools), no cross-compiler.
binary() {
	[ $# -eq 1 ] || die "usage: release.sh binary x86_64|aarch64"
	case "$1" in
	x86_64 | aarch64) ;;
	*) die "unsupported architecture '$1'" ;;
	esac
	target="$1-unknown-linux-musl"
	cargo build --release --locked --target "$target"
	mkdir -p "$dist"
	install -m 755 "target/$target/release/zinkhole" "$dist/zinkhole-$1-linux-musl"
	echo "built $dist/zinkhole-$1-linux-musl ($(version))"
}

# dist/docker/<platform>/zinkhole, as the Dockerfile's BINARY=dist expects.
image_layout() {
	for pair in x86_64:amd64 aarch64:arm64; do
		arch=${pair%%:*}
		platform=${pair#*:}
		[ -e "$dist/zinkhole-$arch-linux-musl" ] || die "missing $dist/zinkhole-$arch-linux-musl: run 'binary $arch' first"
		mkdir -p "$dist/docker/linux/$platform"
		install -m 755 "$dist/zinkhole-$arch-linux-musl" "$dist/docker/linux/$platform/zinkhole"
	done
	echo "laid out $dist/docker for the image build"
}

bundle() {
	for arch in x86_64 aarch64; do
		[ -e "$dist/zinkhole-$arch-linux-musl" ] || die "missing $dist/zinkhole-$arch-linux-musl: run 'binary $arch' first"
	done
	# The container's updater travels with the release it belongs to; `update`
	# fetches it from there (docs/adr/0005). The Proxmox install scripts
	# themselves are served from the repository, as the community-scripts
	# engine expects (deploy/proxmox/ct, deploy/proxmox/install).
	install -m 755 deploy/proxmox/update.sh "$dist/update.sh"
	# MIT asks for the notice to accompany copies of the software.
	install -m 644 LICENSE "$dist/LICENSE"
	# What deploy/install.sh needs next to it. The Proxmox installer and `update`
	# use it instead of GitHub's source archive, which has no checksum we control.
	tar -czf "$dist/zinkhole-deploy.tar.gz" deploy/install.sh deploy/zinkhole.service deploy/openrc/zinkhole config.example.toml
	(cd "$dist" && rm -f SHA256SUMS && sha256sum -- * >SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS)
	echo "bundled $(version):"
	(cd "$dist" && ls -l)
}

publish() {
	dry=no
	[ "${1:-}" = "--dry-run" ] && dry=yes
	[ -e "$dist/SHA256SUMS" ] || die "run 'bundle' first"
	tag=${GITHUB_REF_NAME:?}
	check_tag "$tag"
	v=$(version)
	notes="zinkhole $v

Verify downloads with SHA256SUMS."
	if [ "$dry" = yes ]; then
		for file in "$dist"/*; do
			echo "would upload $(basename "$file")"
		done
		echo "would create release $tag"
		return 0
	fi
	# gh reads GH_TOKEN. Release assets are served at
	# .../releases/latest/download/<name> and .../releases/download/<tag>/<name>.
	gh release create "$tag" "$dist"/* --verify-tag --title "$tag" --notes "$notes"
	echo "released $tag"
}

[ $# -ge 1 ] || die "usage: release.sh version|check-tag|binary|image-layout|bundle|publish"
cmd=$1
shift
case "$cmd" in
version) version ;;
check-tag) check_tag "$@" ;;
binary) binary "$@" ;;
image-layout) image_layout ;;
bundle) bundle ;;
publish) publish "$@" ;;
*) die "unknown command '$cmd'" ;;
esac
