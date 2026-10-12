# dnsblock container image.
#
#   docker build -t dnsblock .                    # FROM scratch (default, ~1.5 MB)
#   docker build -t dnsblock:alpine --target alpine .   # with a shell, for debugging
#   docker run -d --name dnsblock -p 53:53/udp -p 53:53/tcp dnsblock
#
# Use your own config by mounting it over the default:
#   -v /path/to/config.yaml:/etc/dnsblock/config.yaml:ro
# Reload it with `docker kill -s HUP dnsblock`, log statistics with
# `docker kill -s USR1 dnsblock`. See docker-compose.yml for a hardened setup.
#
# The build cross-compiles with Zig on the build machine's architecture, so
# images for other architectures build without emulation:
#   docker buildx build --platform linux/amd64,linux/arm64 -t dnsblock .

ARG ALPINE_VERSION=3.24.2

# --- Build: a static binary (Zig talks to the Linux kernel directly; no libc) --
FROM --platform=$BUILDPLATFORM alpine:${ALPINE_VERSION} AS build
ARG BUILDARCH
ARG TARGETARCH
ARG ZIG_VERSION=0.17.0
# SHA-256 of the official tarballs, from https://ziglang.org/download/index.json
ARG ZIG_SHA256_AMD64=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
ARG ZIG_SHA256_ARM64=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8

# ca-certificates: the bundle is copied into the scratch image below.
RUN apk add --no-cache xz ca-certificates
RUN set -eu; \
    case "$BUILDARCH" in \
        amd64) arch=x86_64;  sha256="$ZIG_SHA256_AMD64" ;; \
        arm64) arch=aarch64; sha256="$ZIG_SHA256_ARM64" ;; \
        *) echo "unsupported build architecture: $BUILDARCH" >&2; exit 1 ;; \
    esac; \
    tarball="zig-$arch-linux-$ZIG_VERSION.tar.xz"; \
    wget -q "https://ziglang.org/download/$ZIG_VERSION/$tarball"; \
    echo "$sha256  $tarball" | sha256sum -c -; \
    mkdir /opt/zig; \
    tar -xJf "$tarball" -C /opt/zig --strip-components=1; \
    rm "$tarball"
ENV PATH="/opt/zig:$PATH"

WORKDIR /src
COPY build.zig build.zig.zon ./
COPY src ./src
RUN set -eu; \
    case "$TARGETARCH" in \
        amd64) target=x86_64-linux-musl ;; \
        arm64) target=aarch64-linux-musl ;; \
        arm)   target=arm-linux-musleabihf ;; \
        *) echo "unsupported target architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    zig build --release -Dstrip=true -Dtarget="$target" --prefix /out

# --- Alpine runtime (docker build --target alpine): has a shell -------------
FROM alpine:${ALPINE_VERSION} AS alpine
RUN apk add --no-cache ca-certificates \
    && addgroup -S dnsblock \
    && adduser -S -D -H -h /var/empty -s /sbin/nologin -G dnsblock dnsblock
COPY --from=build /out/bin/dnsblock /usr/local/bin/dnsblock
COPY config.example.yaml /etc/dnsblock/config.yaml
USER dnsblock
EXPOSE 53/udp 53/tcp
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD ["/usr/local/bin/dnsblock", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/dnsblock"]
CMD ["--config", "/etc/dnsblock/config.yaml"]

# --- Default runtime: nothing but the binary, CA certificates and config ----
FROM scratch
# For DNS over TLS and https:// blocklists. Docker provides /etc/resolv.conf
# and /etc/hosts, which list downloads use to resolve names.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/bin/dnsblock /usr/local/bin/dnsblock
COPY config.example.yaml /etc/dnsblock/config.yaml

# Unprivileged (there is no /etc/passwd, so a numeric user). Docker lets
# containers bind ports below 1024 without privileges
# (net.ipv4.ip_unprivileged_port_start=0), so port 53 works.
USER 65532:65532
EXPOSE 53/udp 53/tcp

# Asks the server for "localhost", which it answers itself, so the check does
# not depend on upstream servers.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD ["/usr/local/bin/dnsblock", "--healthcheck"]

# dnsblock handles SIGTERM itself, so no init process is needed.
ENTRYPOINT ["/usr/local/bin/dnsblock"]
CMD ["--config", "/etc/dnsblock/config.yaml"]
