# syntax=docker/dockerfile:1
# Multi-arch image using pre-built musl binaries from CI.
# Build context must contain: vane-linux-amd64, vane-linux-arm64

FROM alpine:3.20

ARG TARGETARCH
ARG VERSION=dev

LABEL org.opencontainers.image.title="Vane"
LABEL org.opencontainers.image.description="Vane Network Manager (Rust)"
LABEL org.opencontainers.image.version="${VERSION}"

# Runtime deps (ca-certs for ACME/HTTPS, tzdata for correct time display)
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy the correct binary based on build platform
COPY vane-linux-amd64 vane-linux-amd64
COPY vane-linux-arm64 vane-linux-arm64

RUN if [ "$TARGETARCH" = "arm64" ]; then \
      cp vane-linux-arm64 vane; \
    else \
      cp vane-linux-amd64 vane; \
    fi && \
    chmod +x vane && \
    rm -f vane-linux-amd64 vane-linux-arm64

VOLUME ["/app/data"]
EXPOSE 4455

ENV RUST_LOG=vane=info

ENTRYPOINT ["/app/vane"]
CMD ["--config", "/app/data"]
