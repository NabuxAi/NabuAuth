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

############################
# Stage 2: Runtime
############################
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app
COPY --from=build /out/nabuauth /app/nabuauth

# The app registry is baked in so the server boots out of the box. It holds no
# secrets — every client secret is read from its own env var at startup — so
# shipping it inside the image is safe. Mount your own file at /app/apps.yaml to
# override it.
COPY apps.yaml /app/apps.yaml
ENV NABUAUTH_CONFIG=/app/apps.yaml

EXPOSE 8099

ENTRYPOINT ["/app/nabuauth"]
