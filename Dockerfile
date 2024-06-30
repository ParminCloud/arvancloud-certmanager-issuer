ARG GO_VERSION=1.21
ARG DEBIAN_VERSION=bookworm

FROM registry.docker.ir/golang:${GO_VERSION}-${DEBIAN_VERSION} AS build_base

WORKDIR /workspace
ENV CGO_ENABLED=0

RUN apt-get update && \
	apt-get install -y git

FROM build_base AS build_deps

COPY go.mod .
COPY go.sum .

RUN go mod download

FROM build_deps AS build

COPY . .

RUN go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM registry.docker.ir/debian:${DEBIAN_VERSION}-slim

RUN apt-get update && \
	apt-get install -y ca-certificates && \
	update-ca-certificates

COPY --from=build /workspace/webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]
