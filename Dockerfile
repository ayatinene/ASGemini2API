FROM golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS builder

ARG TARGETARCH=arm64

WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN mkdir -p /out/usr/local/bin /out/etc/ssl/certs /out/inputs /out/state /out/tmp && \
    CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags="-s -w" -o /out/usr/local/bin/asgemini2api ./cmd/asgemini2api && \
    cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ca-certificates.crt && \
    printf 'root:x:0:0:root:/root:/sbin/nologin\nasgemini:x:1000:1000:asgemini:/tmp:/sbin/nologin\n' > /out/etc/passwd && \
    printf 'root:x:0:\nasgemini:x:1000:\n' > /out/etc/group && \
    printf 'hosts: files dns\n' > /out/etc/nsswitch.conf && \
    chmod 0755 /out/usr/local/bin/asgemini2api /out/inputs && \
    chmod 0700 /out/state && \
    chmod 1777 /out/tmp && \
    chown -R 1000:1000 /out/inputs /out/state


FROM scratch AS runtime

LABEL org.opencontainers.image.title="ASGemini2API" \
      org.opencontainers.image.description="Headless Android Studio Gemini OpenAI-compatible proxy" \
      org.opencontainers.image.source="https://github.com/ayatinene/ASGemini2API"

ENV HOME=/tmp \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    ASGEMINI_INPUT_DIR=/inputs \
    ASGEMINI_STATE_DIR=/state

COPY --from=builder /out/ /

USER 1000:1000
WORKDIR /state

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/asgemini2api", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/asgemini2api"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
