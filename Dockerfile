# syntax=docker/dockerfile:1
# Cross-compiles on the build platform; no emulation needed for multi-arch.
FROM --platform=$BUILDPLATFORM golang:1.26.3-bookworm AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/orchivio-github-adapter ./cmd/orchivio-github-adapter

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/orchivio-github-adapter /orchivio-github-adapter
ENTRYPOINT ["/orchivio-github-adapter"]
