# NovaVeil_WARP

NovaVeil_WARP 是单容器 Cloudflare WARP 代理，同时提供 SOCKS5（默认 `:1080`）和 HTTP 代理（默认 `:8080`）。
进程内池化多个 WARP 隧道，每个隧道一个出口 IP。
控制 API 收到 429 回报后淘汰对应隧道并后台轮换，403 视为形态/身份信号不换出口。
同时提供稳定的槽位账号，把并发请求固定到不同出口。

纯用户态（WireGuard-go + gVisor netstack），**不需要 TUN 设备、root、NET_ADMIN**。

## 原理

```
启动 → 注册第 1 个隧道（同步）→ 后台填到池底（默认 3 个，12 秒间隔）
运行 → 池里常驻 N 个热隧道（N 个不同出口段）
       → 每个 SOCKS5 / HTTP 代理连接轮询取一个
       → HTTP 代理支持 CONNECT（HTTPS 隧道）和 absolute-URI（纯 HTTP 转发）
       → 每 60 秒巡检空闲隧道，探不通即淘汰补位
       → 控制 API 报 429 → 轮换该隧道 → 后台注册新隧道替换
       → 槽位账号 warp-0..warp-N-1 固定到各自出口
       → 用户永远拿到热隧道，不等注册
```

WARP 免费注册无次数上限，每次注册拿到独立 WireGuard 密钥和出口 IP，因此可以无限轮换。

### 两种 IP 多样性档位

| 模式 | 效果 | 要求 |
|---|---|---|
| 不开 `source-ipv6` | 每次注册新 /128 出口 IP，但可能落在同一个 /64 内 | 无 |
| 开 `source-ipv6` | 每个隧道绑定 /64 前缀内随机源地址，不同源 → 不同公网 /64 → 真正跨配额域 | Linux + 宿主机有路由到的 IPv6 /64 |

### 地址族：IPv6 优先，IPv4 兜底

默认 `-stack ipv6`。v6 隧道建不起来时（注册不带 v6 地址、外层源绑定失败、v6 探测不通），用**同一份注册**里的 v4 地址重建，不重新注册、不浪费 12 秒注册间隔。

v4 出口是 Cloudflare NAT 后的共享地址，配额通常已被别人耗尽，所以这档只是保命，不是长久之计。`/status` 的 `Fallback` 字段显示当前有几个出口在走 v4；非零就说明 v6 链路有问题。

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

### 槽位账号

`GET /slots` 返回 `slot 0..size-1` 的稳定槽位表，每格绑定一个在岗出口。
槽位被惩罚或轮换时会先绑定新出口再释放旧出口，`generation` 随之加一。
HTTP 代理从 `Proxy-Authorization: Basic` 的用户名读取槽位，SOCKS5 走 RFC1929；
密码忽略，未带 `warp-` 前缀的用户名继续使用原来的轮询行为。

```sh
# HTTP CONNECT：用户名 warp-0，密码任意
curl -x http://warp-0:any@127.0.0.1:8080 https://api.ipify.org

# SOCKS5：同样用 warp-<slot> 作为用户名
curl -x socks5h://warp-0:any@127.0.0.1:1080 https://api.ipify.org
```

未知槽位返回 407，忙/冷却/无出口返回 503 与 `Retry-After`，不会静默换到别的出口。
槽位认证只用于选路，不构成安全边界；监听地址仍应只绑 `127.0.0.1`。

### 参数

| 参数 | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `-socks` | `SOCKS5_LISTEN` | `:1080` | SOCKS5 监听地址 |
| `-http` | `HTTP_LISTEN` | `:8080` | HTTP 代理监听地址（传空字符串禁用） |
| `-control` | `CONTROL_LISTEN` | `:1081` | 控制 API 监听地址 |
| `-pool-size` | `WARP_POOL_SIZE` | `4` | 常驻热隧道与槽位数量（1-32） |
| `-min-pool` | `WARP_MIN_POOL` | `3` | 补池目标下限（正常等于 `pool-size`） |
| `-stack` | `WARP_STACK` | `ipv6` | 隧道地址族：ipv4/ipv6/dual |
| `-no-ipv4-fallback` | `WARP_NO_IPV4_FALLBACK` | `false` | 禁止 v6 建不起来时降级 v4 |
| `-health-interval` | `WARP_HEALTH_INTERVAL` | `60s` | 周期巡检间隔，`0` 关闭 |
| `-source-ipv6` | `WARP_SOURCE_IPV6` | 空 | 外层 IPv6 源前缀（/64 或更短） |
| `-recent-window` | `WARP_RECENT_WINDOW` | `10s` | 无参惩罚回看时间窗口 |
| `-cooldown` | `WARP_COOLDOWN` | `60s` | 被惩罚的配额段重新可用前的等待时长，负值表示不冷却 |
| `-mem-limit` | `WARP_MEM_LIMIT` | `300MiB` | 进程内存上限，`0` 表示不限制 |

### 控制 API

```sh
# 查看池状态
curl http://localhost:1081/snapshot
# {"Stack":"ipv6","Size":4,"MinSize":3,"Active":3,"Standby":2,"Cooling":0,"Fallback":0,"Egress":[...]}

# 详细状态：多一份冷却名单与解锁时刻
curl http://localhost:1081/status

# 槽位表：每个 slot 的出口、/64 或 /32 前缀、状态、在途数与 generation
curl http://localhost:1081/slots
# {"size":4,"updated_at":"...","slots":[{"slot":0,"account":"warp-0",...}]}

# 健康检查
curl http://localhost:1081/healthz

# 惩罚特定出口（NovaVeil 知道 egress IP 时）
curl -X POST 'http://localhost:1081/penalize?egress=2606:4700:...&reason=429'

# 惩罚最近一次拨号的单个出口（NovaVeil 不知道具体 IP 时）
curl -X POST http://localhost:1081/penalize
# {"penalized":1}

# 主动换桶：淘汰全部在岗出口，后台补新段
curl -X POST 'http://localhost:1081/rotate?all=1'
# {"rotated":3}

# 立刻全量巡检，探不通的当场淘汰
curl -X POST http://localhost:1081/probe
# {"dropped":0}
```

被淘汰的出口段进入冷却，默认 60 秒后重新可用（`-cooldown` 可调，负值表示不冷却）。冷却期间重新抽到同一段会被丢弃重抽。冷却取短值是刻意的：换段成本远低于让池子空掉的成本，早期实现把段锁到下一个 UTC 0 点（最长 6 小时），一次全池换桶就能把池封死。

### 轮换策略

429 触发轮换，403 不触发（形态/身份信号，换出口无益）。
目标站自身的 DNS 失败、连接拒绝等拨号错误不触发轮换，避免误杀健康出口。
轮换先复用旧注册、换外层源地址做 soft restart；新出口的 /64（IPv4 为 /32）与旧出口相同才做 full re-key。
soft restart 落点若仍在被封禁的段上，轮换会自动改走 full re-key 换段重建，不会原地重试。
全池轮换串行执行，相邻两次至少间隔 4 秒；单出口 key 每小时最多 60 次，全池 full re-key 每小时最多 60 次。
连续失败按 15 * 2^n 秒退避，封顶 300 秒；轮换失败、退避或预算耗尽时旧出口保持退役与冷却，由后台补池提供替代容量，不会无限重试。

## Docker

```sh
docker build -t novaveil_warp .
docker run -d --name NovaVeil_WARP_socks5 \
  -p 127.0.0.1:1080:1080 -p 127.0.0.1:8080:8080 -p 127.0.0.1:1081:1081 \
  --memory=300m --cpus=1.0 \
  -e WARP_MIN_POOL=3 \
  -e WARP_POOL_SIZE=8 \
  novaveil_warp
```

容器/服务名默认用 `NovaVeil_WARP_socks5`；镜像仓库名用小写 `novaveil_warp`（Docker 要求）。

内存默认上限 300MB：进程内 `debug.SetMemoryLimit` 取上限的 80% 让 GC 提前回收，容器 `--memory=300m` 兜底硬约束，两者都要配。

端口务必只绑 `127.0.0.1`：SOCKS5 与 HTTP 代理默认无认证，槽位用户名只用于选路；绑 `0.0.0.0` 等于在公网开一个开放代理，会被扫段打爆。远程机器用 SSH 隧道接入：

```sh
ssh -N -L 1080:127.0.0.1:1080 -L 1081:127.0.0.1:1081 user@vps
```

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
    mem_limit: 300m
    cpus: "1.0"
    environment:
      WARP_MIN_POOL: "3"
      WARP_POOL_SIZE: "8"
      WARP_STACK: "ipv6"
      WARP_HEALTH_INTERVAL: "60s"
      WARP_COOLDOWN: "60s"
      WARP_MEM_LIMIT: "300MiB"
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

NovaVeil 检测到代理地址含 `NovaVeil_WARP_socks5` 时，自动在 429 后向
`http://NovaVeil_WARP_socks5:1081/penalize` 发异步 POST，淘汰最近一次拨号的出口（单次最多 1 个）并重试。
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
