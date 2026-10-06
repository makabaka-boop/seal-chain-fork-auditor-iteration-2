# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.23-bookworm AS build

WORKDIR /src

# Cache dependencies first (this module has no third-party deps, but keeping
# the conventional two-copy layout makes future additions cheap).
COPY go.mod ./
RUN go mod download

COPY . .

# Static binary, no CGO, fully reproducible build flags.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/sealaudit \
    ./cmd/sealaudit

# ---- runtime stage ----
# distroless base: no shell, no package manager, minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /
COPY --from=build /out/sealaudit /sealaudit

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/sealaudit"]
