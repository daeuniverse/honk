# The image repackages a published release; it compiles nothing.
# Build: docker build --build-arg HONK_VERSION=<version without v> -t honk .

# Downloads run on the build host, so the multi-arch build needs no emulation.
FROM --platform=$BUILDPLATFORM alpine:3.24 AS fetch

ARG HONK_VERSION
ARG TARGETARCH

# The geodata pins live in .github/ci/pins.env alone.
RUN --mount=type=bind,source=.github/ci/pins.env,target=/tmp/pins.env \
    set -eux; \
    test -n "$HONK_VERSION"; \
    case "$TARGETARCH" in \
        amd64) arch=x86_64 ;; \
        arm64) arch=aarch64 ;; \
        *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    . /tmp/pins.env; \
    pkg="honk-core-v${HONK_VERSION}-${arch}-unknown-linux-musl-full"; \
    release="https://github.com/daeuniverse/honk/releases/download/v${HONK_VERSION}"; \
    mkdir /work /out; \
    cd /work; \
    wget -q "$release/SHA256SUMS" "$release/$pkg.tar.gz"; \
    grep "  $pkg.tar.gz\$" SHA256SUMS | sha256sum -c -; \
    tar -xzof "$pkg.tar.gz"; \
    install -D -m 0755 "$pkg/honk-core" /out/usr/local/bin/honk-core; \
    rm "$pkg/honk-core"; \
    mkdir -p /out/usr/local/share/doc; \
    mv "$pkg" /out/usr/local/share/doc/honk; \
    share=/out/usr/local/share/honk; \
    mkdir -p "$share"; \
    wget -q -O "$share/geosite.dat" "https://github.com/v2fly/domain-list-community/releases/download/$GEOSITE_TAG/dlc.dat"; \
    echo "$GEOSITE_SHA256  $share/geosite.dat" | sha256sum -c -; \
    wget -q -O "$share/geoip.dat" "https://github.com/v2fly/geoip/releases/download/$GEOIP_TAG/geoip.dat"; \
    echo "$GEOIP_SHA256  $share/geoip.dat" | sha256sum -c -

# Alpine, as in dae's image: the release binary is static, and the base adds a shell and
# the CA bundle that the platform certificate verifier reads.
FROM alpine:3.24

# Full iproute2 (ip, tc, ss) and nft for inspecting routes, rules, tc filters and the
# NFQUEUE table from inside the container; busybox ip lacks most of that.
RUN apk add --no-cache iproute2 nftables

COPY --from=fetch /out/ /
COPY --chmod=0600 install/docker.dae /etc/honk/config.dae

ENTRYPOINT ["honk-core", "--config", "/etc/honk/config.dae"]
