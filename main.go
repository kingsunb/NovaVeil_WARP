// NovaVeil_WARP: 单容器 Cloudflare WARP 代理, 同时提供 SOCKS5 和 HTTP 正向代理,
// 进程内池化多个 WARP 隧道, 每个隧道一个出口 IP. 控制 API 收到 403/429 回报后
// 淘汰对应隧道并后台注册新的.
//
// 纯用户态 (WireGuard-go + gVisor netstack), 不需要 TUN/root/NET_ADMIN.
// 代码改编自 github.com/jasonxu114514/opencode2api (internal/warp), MIT 许可.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"NovaVeil_WARP/internal/httpproxy"
	"NovaVeil_WARP/internal/socks5"
	"NovaVeil_WARP/internal/warp"
)

func main() {
	var (
		socksListen   = flag.String("socks", getenv("SOCKS5_LISTEN", ":1080"), "SOCKS5 监听地址")
		httpListen    = flag.String("http", getenv("HTTP_LISTEN", ":8080"), "HTTP 代理监听地址 (传空字符串禁用)")
		controlListen = flag.String("control", getenv("CONTROL_LISTEN", ":1081"), "控制 API 监听地址")
		poolSize      = flag.Int("pool-size", getenvInt("WARP_POOL_SIZE", 4), "WARP 隧道池上限 (1-32)")
		minPool       = flag.Int("min-pool", getenvInt("WARP_MIN_POOL", warp.DefaultMinSize), "空闲时保活的出口下限 (至少 2)")
		stack         = flag.String("stack", getenv("WARP_STACK", "ipv6"), "隧道地址族: ipv4/ipv6/dual")
		noFallback    = flag.Bool("no-ipv4-fallback", getenvBool("WARP_NO_IPV4_FALLBACK", false), "禁止 v6 不可用时降级 v4")
		healthEvery   = flag.Duration("health-interval", getenvDuration("WARP_HEALTH_INTERVAL", 60*time.Second), "周期巡检间隔, 0 关闭")
		sourceIPv6    = flag.String("source-ipv6", getenv("WARP_SOURCE_IPV6", ""), "外层 IPv6 源前缀 (/64 或更短), 留空则不绑定")
		recentWindow  = flag.Duration("recent-window", getenvDuration("WARP_RECENT_WINDOW", 10*time.Second), "控制 API 无参惩罚时回看的时间窗口")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	stackType, err := warp.ParseStack(*stack)
	if err != nil {
		logger.Error("invalid stack", "err", err)
		os.Exit(1)
	}

	var sourcePrefix netip.Prefix
	if *sourceIPv6 != "" {
		sourcePrefix, err = netip.ParsePrefix(*sourceIPv6)
		if err != nil {
			logger.Error("invalid source-ipv6", "err", err)
			os.Exit(1)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("starting WARP pool", "min", *minPool, "size", *poolSize, "stack", stackType, "source_ipv6", sourcePrefix)
	pool, err := warp.NewWithOptions(ctx, logger, warp.Options{
		Size:                *poolSize,
		MinSize:             *minPool,
		Stack:               stackType,
		DisableIPv4Fallback: *noFallback,
		SourceIPv6:          sourcePrefix,
	})
	if err != nil {
		logger.Error("WARP pool init failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()
	pool.StartHealthCheck(*healthEvery)

	tracker := newRecentTracker(*recentWindow)

	dial := makeDialFunc(pool, tracker, logger)

	srv := &socks5.Server{
		Dial:    dial,
		Timeout: 30 * time.Second,
	}

	go startSOCKS5(ctx, *socksListen, srv, logger)
	if *httpListen != "" {
		proxy := &httpproxy.Server{
			Dial:    httpproxy.DialFunc(dial),
			Timeout: 30 * time.Second,
		}
		go startHTTPProxy(ctx, *httpListen, proxy, logger)
	}
	go startControl(ctx, *controlListen, pool, tracker, logger)

	logger.Info("NovaVeil_WARP ready", "socks", *socksListen, "http", *httpListen, "control", *controlListen)
	<-ctx.Done()
	logger.Info("shutting down")
}

// makeDialFunc 返回 SOCKS5 / HTTP 代理使用的拨号函数: 从 WARP 池获取租约,
// 穿透隧道拨号, 连接关闭时释放租约. 拨号失败立即惩罚该隧道.
func makeDialFunc(pool *warp.Pool, tracker *recentTracker, logger *slog.Logger) socks5.DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		lease, err := pool.Acquire(ctx)
		if err != nil {
			return nil, err
		}
		dialNet := lease.DialNetwork()
		if dialNet == "" {
			dialNet = network
		}
		conn, err := lease.DialContext(ctx, dialNet, addr)
		if err != nil {
			pool.Fail(lease, err.Error())
			lease.Release()
			return nil, err
		}
		egress := lease.EgressAddr()
		if egress != "" {
			tracker.Record(egress)
		}
		return &leaseConn{Conn: conn, lease: lease}, nil
	}
}

// leaseConn 包装 WARP 隧道连接, Close 时释放租约.
type leaseConn struct {
	net.Conn
	lease *warp.Lease
	once  sync.Once
}

func (c *leaseConn) Close() error {
	c.once.Do(func() {
		c.lease.Release()
	})
	return c.Conn.Close()
}

func (c *leaseConn) CloseWrite() error {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// --- SOCKS5 监听 ---

func startSOCKS5(ctx context.Context, addr string, srv *socks5.Server, logger *slog.Logger) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("socks5 listen failed", "err", err)
		os.Exit(1)
	}
	logger.Info("socks5 listening", "addr", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Warn("socks5 accept failed", "err", err)
			continue
		}
		go func() {
			if err := srv.Serve(ctx, conn); err != nil {
				logger.Debug("socks5 session ended", "err", err)
			}
		}()
	}
}

// --- HTTP 代理监听 ---

func startHTTPProxy(ctx context.Context, addr string, handler http.Handler, logger *slog.Logger) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("http proxy listen failed", "err", err)
		os.Exit(1)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	logger.Info("http proxy listening", "addr", addr)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
		logger.Error("http proxy failed", "err", err)
	}
}

// --- 控制 API ---

func startControl(ctx context.Context, addr string, pool *warp.Pool, tracker *recentTracker, logger *slog.Logger) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		snap := pool.Snapshot()
		if snap.Active > 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	mux.HandleFunc("GET /snapshot", func(w http.ResponseWriter, r *http.Request) {
		snap := pool.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snap)
	})

	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		status := struct {
			warp.Snapshot
			CoolingUntil map[string]time.Time `json:"CoolingUntil"`
		}{Snapshot: pool.Snapshot(), CoolingUntil: pool.CoolingUntil()}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	mux.HandleFunc("POST /penalize", func(w http.ResponseWriter, r *http.Request) {
		egress := strings.TrimSpace(r.URL.Query().Get("egress"))
		reason := strings.TrimSpace(r.URL.Query().Get("reason"))
		if reason == "" {
			reason = "control-api"
		}

		var penalized int
		if egress != "" {
			if pool.PenalizeByEgress(egress, reason) {
				penalized = 1
			}
		} else {
			recent := tracker.Recent()
			penalized = pool.PenalizeRecent(recent, reason)
		}

		logger.Info("penalize request", "egress", egress, "penalized", penalized)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"penalized": penalized})
	})

	mux.HandleFunc("POST /rotate", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		egress := strings.TrimSpace(query.Get("egress"))
		reason := strings.TrimSpace(query.Get("reason"))
		if reason == "" {
			reason = "control-api"
		}
		rotated := 0
		switch {
		case query.Get("all") != "":
			rotated = pool.RotateAll(reason)
		case egress != "":
			if pool.PenalizeByEgress(egress, reason) {
				rotated = 1
			}
		default:
			rotated = pool.PenalizeRecent(tracker.Recent(), reason)
		}
		logger.Info("rotate request", "egress", egress, "rotated", rotated)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"rotated": rotated})
	})

	mux.HandleFunc("POST /probe", func(w http.ResponseWriter, r *http.Request) {
		egress := strings.TrimSpace(r.URL.Query().Get("egress"))
		probeCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Minute)
		defer cancel()
		dropped := 0
		if egress != "" {
			healthy, found := pool.ProbeEgress(probeCtx, egress)
			if found && !healthy {
				dropped = 1
			}
		} else {
			dropped = pool.Check(probeCtx)
		}
		logger.Info("probe request", "egress", egress, "dropped", dropped)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"dropped": dropped})
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	logger.Info("control API listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("control API failed", "err", err)
	}
}

// --- 最近出口追踪 ---

type recentTracker struct {
	mu      sync.Mutex
	entries []egressStamp
	window  time.Duration
}

type egressStamp struct {
	addr string
	at   time.Time
}

func newRecentTracker(window time.Duration) *recentTracker {
	return &recentTracker{window: window}
}

func (rt *recentTracker) Record(addr string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	now := time.Now()
	rt.entries = append(rt.entries, egressStamp{addr: addr, at: now})
	cutoff := now.Add(-rt.window)
	kept := rt.entries[:0]
	for _, e := range rt.entries {
		if e.at.After(cutoff) {
			kept = append(kept, e)
		}
	}
	rt.entries = kept
}

func (rt *recentTracker) Recent() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	cutoff := time.Now().Add(-rt.window)
	seen := make(map[string]bool)
	var result []string
	for _, e := range rt.entries {
		if e.at.After(cutoff) && !seen[e.addr] {
			seen[e.addr] = true
			result = append(result, e.addr)
		}
	}
	return result
}

// --- 环境变量辅助 ---

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func getenvBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}
