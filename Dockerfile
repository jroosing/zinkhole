# zinkhole container image.
#
#   docker build -t zinkhole .                            # FROM scratch (default)
#   docker build -t zinkhole:alpine --target alpine .     # with a shell, for debugging
#   docker run -d --name zinkhole -p 53:53/udp -p 53:53/tcp zinkhole
#
# Use your own config by mounting it over the default:
#   -v /path/to/config.toml:/etc/zinkhole/config.toml:ro
# Reload it with `docker kill -s HUP zinkhole`, log a summary with
# `docker kill -s USR1 zinkhole`. See docker-compose.yml for a hardened setup.
#
# By default the binary is built from source here, for the platform being
# built (other platforms build under emulation). The release images use the
# release binaries instead, built natively per architecture by CI:
#   docker buildx build --build-arg BINARY=dist --platform linux/amd64,linux/arm64 .
# which expects dist/docker/linux/<arch>/zinkhole.

ARG RUST_VERSION=1.99
ARG ALPINE_VERSION=3.24.2
# source: build here; dist: take the binary from dist/docker/<platform>/.
ARG BINARY=source

# --- A static musl binary, built from source --------------------------------
FROM rust:${RUST_VERSION}-alpine AS binary-source
# ring's C parts need a C compiler and musl's headers.
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
    && install -D -m 755 target/release/zinkhole /out/zinkhole

# --- Or the release binary for the platform ---------------------------------
FROM scratch AS binary-dist
ARG TARGETPLATFORM
COPY dist/docker/${TARGETPLATFORM}/zinkhole /out/zinkhole

FROM binary-${BINARY} AS binary

# An empty state directory for replicas (sync), owned by the runtime user,
# so a new named volume on it starts out writable. Made on the build
# platform: a multi-arch build of the default image then runs nothing under
# emulation.
FROM --platform=$BUILDPLATFORM alpine:${ALPINE_VERSION} AS state
RUN install -d -o 65532 -g 65532 /out/state

# --- Alpine runtime (docker build --target alpine): has a shell -------------
FROM alpine:${ALPINE_VERSION} AS alpine
RUN addgroup -S -g 65532 zinkhole \
    && adduser -S -D -H -u 65532 -h /var/empty -s /sbin/nologin -G zinkhole zinkhole
COPY --from=binary /out/zinkhole /usr/local/bin/zinkhole
COPY config.example.toml /etc/zinkhole/config.toml
COPY --from=state --chown=65532:65532 /out/state /var/lib/zinkhole
USER 65532:65532
EXPOSE 53/udp 53/tcp
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD ["/usr/local/bin/zinkhole", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/zinkhole"]
CMD ["serve"]

# --- Default runtime: nothing but the binary and its config -----------------
FROM scratch
# The binary carries its root certificates (for DNS over HTTPS and https://
# lists), so no CA bundle is needed. Docker provides /etc/resolv.conf and
# /etc/hosts, which list downloads use to resolve names.
COPY --from=binary /out/zinkhole /usr/local/bin/zinkhole
COPY config.example.toml /etc/zinkhole/config.toml
# A replica keeps its last synced settings here; mount a volume on it.
COPY --from=state --chown=65532:65532 /out/state /var/lib/zinkhole

# Unprivileged (there is no /etc/passwd, so a numeric user). Docker lets
# containers bind ports below 1024 without privileges
# (net.ipv4.ip_unprivileged_port_start=0), so port 53 works.
USER 65532:65532
EXPOSE 53/udp 53/tcp

# Asks the server for "localhost", which it answers itself, so the check does
# not depend on upstream servers.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD ["/usr/local/bin/zinkhole", "healthcheck"]

# zinkhole handles SIGTERM itself, so no init process is needed. The config
# is /etc/zinkhole/config.toml unless ZINKHOLE_CONFIG or -c says otherwise.
ENTRYPOINT ["/usr/local/bin/zinkhole"]
CMD ["serve"]
