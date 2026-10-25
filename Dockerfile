# 多阶段构建: 编译期用 golang, 运行期用最小 alpine.
# WARP 注册要 HTTPS 访问 api.cloudflareclient.com, 运行期需 ca-certificates.
# 纯用户态, 不需要 TUN/NET_ADMIN/root.

FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /warp-socks5 .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 warp
COPY --from=builder /warp-socks5 /usr/local/bin/warp-socks5
USER 10001
EXPOSE 1080 1081
ENTRYPOINT ["warp-socks5"]
