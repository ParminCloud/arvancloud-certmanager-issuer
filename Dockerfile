# syntax=docker/dockerfile:1

ARG GO_VERSION=1.23
ARG DEBIAN_VERSION=bookworm
ARG DOCKER_REGISTRY=docker.io
ARG LD_FLAGS="-w -extldflags '-static'"

FROM ${DOCKER_REGISTRY}/library/golang:${GO_VERSION}-${DEBIAN_VERSION} AS build_base

WORKDIR /workspace
ENV CGO_ENABLED=0

RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
	--mount=type=cache,target=/var/lib/apt,sharing=locked \
	apt-get update && \
	apt-get install -y git

FROM build_base AS build_deps

COPY --link go.mod ./
COPY --link go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
	go mod download

FROM build_deps AS build
ARG LD_FLAGS

COPY --link . ./

RUN --mount=type=cache,target=/root/.cache/go-build \
	go build -o webhook -ldflags "${LD_FLAGS}" .

FROM ${DOCKER_REGISTRY}/library/debian:${DEBIAN_VERSION}-slim AS runtime

RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
	--mount=type=cache,target=/var/lib/apt,sharing=locked \
	apt-get update && \
	apt-get install -y ca-certificates && \
	update-ca-certificates

COPY --from=build /workspace/webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]
