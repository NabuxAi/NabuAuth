# syntax=docker/dockerfile:1

############################
# Stage 1: Build
############################
FROM golang:1.24-bookworm AS build

WORKDIR /src

# Cache module downloads
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/nabuauth ./cmd/nabuauth

# The unprivileged user the runtime image runs as — the same uid/gid 65532
# "nonroot" the distroless image used to provide.
RUN echo 'nonroot:x:65532:65532:nonroot:/app:/sbin/nologin' > /out/passwd \
 && echo 'nonroot:x:65532:' > /out/group

############################
# Stage 2: Runtime
############################
# scratch, not gcr.io/distroless: the Iran deployment builds on a server that
# gets 403 from gcr.io, so every deploy there failed at this line and the
# instance stayed on an old image. A static Go binary needs only what the
# build stage already has — CA roots for outbound TLS (SMS, mail, Google,
# Telegram), zoneinfo, and a non-root user — and copying those keeps the image
# buildable wherever Docker Hub is.
FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /out/passwd /etc/passwd
COPY --from=build /out/group /etc/group

WORKDIR /app
COPY --from=build /out/nabuauth /app/nabuauth

# The app registry is baked in so the server boots out of the box. It holds no
# secrets — every client secret is read from its own env var at startup — so
# shipping it inside the image is safe. Mount your own file at /app/apps.yaml to
# override it.
COPY apps.yaml /app/apps.yaml
ENV NABUAUTH_CONFIG=/app/apps.yaml

EXPOSE 8099

USER 65532:65532

ENTRYPOINT ["/app/nabuauth"]
