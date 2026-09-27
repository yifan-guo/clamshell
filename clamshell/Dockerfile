FROM golang:1.21 AS build
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 go build -o /clamshell .

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      tpm2-tools curl ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

# Installs the smallstep `step` CLI used to request certs from step-ca.
RUN curl -fsSL -o /tmp/step.tar.gz \
      https://github.com/smallstep/cli/releases/latest/download/step_linux_amd64.tar.gz \
    && tar -xzf /tmp/step.tar.gz -C /tmp \
    && cp /tmp/step_*/bin/step /usr/local/bin/step \
    && rm -rf /tmp/step*

COPY --from=build /clamshell /usr/local/bin/clamshell
RUN mkdir -p /state
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/clamshell"]
