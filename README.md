# NovaVeil_WARP

NovaVeil_WARP 是单容器 Cloudflare WARP 代理，同时提供 SOCKS5（默认 `:1080`）和 HTTP 代理（默认 `:8080`）。
进程内池化多个 WARP 隧道，每个隧道一个出口 IP。
控制 API 收到 403/429 回报后淘汰对应隧道并后台注册新的，实现单容器无限换 IP。

纯用户态（WireGuard-go + gVisor netstack），**不需要 TUN 设备、root、NET_ADMIN**。

## 原理

```
启动 → 注册第 1 个隧道（同步）→ 后台填满池子（默认 4 个，12 秒间隔）
运行 → 池里始终保持 N 个热隧道（N 个不同出口 IP）
       → 每个 SOCKS5 / HTTP 代理连接轮询取一个
       → HTTP 代理支持 CONNECT（HTTPS 隧道）和 absolute-URI（纯 HTTP 转发）
       → 控制 API 报 403/429 → 淘汰该隧道 → 后台注册新隧道替换
       → 用户永远拿到热隧道，不等注册
```

WARP 免费注册无次数上限，每次注册拿到独立 WireGuard 密钥和出口 IP，因此可以无限轮换。

### 两种 IP 多样性档位

| 模式 | 效果 | 要求 |
|---|---|---|
| 不开 `source-ipv6` | 每次注册新 /128 出口 IP，但可能落在同一个 /64 内 | 无 |
| 开 `source-ipv6` | 每个隧道绑定 /64 前缀内随机源地址，不同源 → 不同公网 /64 → 真正跨配额域 | Linux + 宿主机有路由到的 IPv6 /64 |

## 用法

```sh
# 直接运行（SOCKS5 :1080，HTTP 代理 :8080，控制 API :1081）
./NovaVeil_WARP -pool-size 4 -stack ipv6

# 或用环境变量
SOCKS5_LISTEN=:1080 HTTP_LISTEN=:8080 CONTROL_LISTEN=:1081 WARP_POOL_SIZE=8 ./NovaVeil_WARP
```

### HTTP 代理用法

```sh
# 纯 HTTP（absolute-URI 转发）
curl -x http://127.0.0.1:8080 http://example.com

# HTTPS（CONNECT 隧道）
curl -x http://127.0.0.1:8080 https://api.ipify.org
```

### 参数

| 参数 | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `-socks` | `SOCKS5_LISTEN` | `:1080` | SOCKS5 监听地址 |
| `-http` | `HTTP_LISTEN` | `:8080` | HTTP 代理监听地址（传空字符串禁用） |
| `-control` | `CONTROL_LISTEN` | `:1081` | 控制 API 监听地址 |
| `-pool-size` | `WARP_POOL_SIZE` | `4` | WARP 隧道池大小（1-32） |
| `-stack` | `WARP_STACK` | `ipv6` | 隧道地址族：ipv4/ipv6/dual |
| `-source-ipv6` | `WARP_SOURCE_IPV6` | 空 | 外层 IPv6 源前缀（/64 或更短） |
| `-recent-window` | `WARP_RECENT_WINDOW` | `10s` | 无参惩罚回看时间窗口 |

### 控制 API

```sh
# 查看池状态
curl http://localhost:1081/snapshot
# {"Stack":"ipv6","Size":4,"Active":4,"Standby":3,"Cooling":0,"Egress":["2606:...","2606:...",...]}

# 健康检查
curl http://localhost:1081/healthz

# 惩罚特定出口（NovaVeil 知道 egress IP 时）
curl -X POST 'http://localhost:1081/penalize?egress=2606:4700:...&reason=429'

# 惩罚最近用过的出口（NovaVeil 不知道具体 IP 时）
curl -X POST http://localhost:1081/penalize
# {"penalized":1}
```

## Docker

```sh
docker build -t novaveil_warp .
docker run -d --name NovaVeil_WARP_socks5 \
  -p 1080:1080 -p 8080:8080 -p 1081:1081 \
  -e WARP_POOL_SIZE=8 \
  novaveil_warp
```

容器/服务名默认用 `NovaVeil_WARP_socks5`；镜像仓库名用小写 `novaveil_warp`（Docker 要求）。

无需 `--privileged`、`--cap-add`、`--device`。

## NovaVeil 集成

### 1. docker-compose 加 sidecar

服务名默认是 `NovaVeil_WARP_socks5`，NovaVeil 靠这个名字匹配渠道代理并自动推导控制 API 地址。

```yaml
networks:
  internal:
    driver: bridge

services:
  novaveil:
    # ... 现有配置不动 ...
    networks:
      - internal

  NovaVeil_WARP_socks5:
    build: ./NovaVeil_WARP  # 指向本仓库目录，按实际路径调整
    container_name: NovaVeil_WARP_socks5
    restart: unless-stopped
    environment:
      WARP_POOL_SIZE: "8"
      WARP_STACK: "ipv6"
      # WARP_SOURCE_IPV6: "2001:db8::/64"  # 有 /64 前缀才填
    networks:
      - internal
    # 无需 cap_add / devices / privileged
```

### 2. NovaVeil 渠道配置

在 NovaVeil 控制台把 OpenCode 免费档渠道的代理设为：

```
socks5://NovaVeil_WARP_socks5:1080
```

如果该渠道只接受 HTTP 代理，则改用：

```
http://NovaVeil_WARP_socks5:8080
```

NovaVeil 检测到代理地址含 `NovaVeil_WARP_socks5` 时，自动在 403/429 后向
`http://NovaVeil_WARP_socks5:1081/penalize` 发异步 POST，淘汰当前出口 IP 并重试。
惩罚会关闭旧出口上已建立的连接（替换隧道就绪后立即断开），强制客户端重新建连并拿到新 IP；否则长连接会继续复用旧出口。

### 3. 工作流程

```
NovaVeil 请求 → socks5://NovaVeil_WARP_socks5:1080（或 http://NovaVeil_WARP_socks5:8080）
               → WARP 隧道(IP-A) → 上游
上游返回 429
NovaVeil → POST http://NovaVeil_WARP_socks5:1081/penalize  (异步, 不阻塞)
         → WARP 容器淘汰 IP-A, 后台注册新隧道(IP-B)
NovaVeil 重试 → 同一代理地址 → WARP 隧道(IP-B) → 成功
```

## 致谢

`internal/warp` 改编自 [opencode2api](https://github.com/jasonxu114514/opencode2api) 的 `internal/warp` 包，
后者改编自 [sudogeeker/ai-route](https://github.com/sudogeeker/ai-route)（MIT 许可）。
