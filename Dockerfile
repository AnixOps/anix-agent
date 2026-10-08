# Build go
FROM golang:1.25.0-alpine AS builder
ARG VERSION=v4.2.0-rc.3
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN GOEXPERIMENT=jsonv2 go mod download
RUN GOEXPERIMENT=jsonv2 go build -v -o anix-agent \
    -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor" \
    -ldflags "-X 'github.com/AnixOps/anix-agent/v4/cmd.version=${VERSION}' -s -w"

# Release
FROM  alpine
LABEL org.opencontainers.image.title="AnixOps Agent" \
      org.opencontainers.image.source="https://github.com/AnixOps/anix-agent"
# 安装必要的工具包
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir -p /etc/anixops/agent /etc/V2bX \
    && ln -s /etc/anixops/agent/config.json /etc/V2bX/config.json
COPY --from=builder /app/anix-agent /usr/local/bin/anix-agent
RUN ln -s /usr/local/bin/anix-agent /usr/local/bin/V2bX

ENTRYPOINT ["/bin/sh", "-c", "config_path=\"${ANIX_AGENT_CONFIG:-/etc/anixops/agent/config.json}\"; if [ ! -e \"${config_path}\" ] && [ -e /etc/V2bX/config.json ]; then config_path=/etc/V2bX/config.json; fi; exec anix-agent server --config \"${config_path}\""]
