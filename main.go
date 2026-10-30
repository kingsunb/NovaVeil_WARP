// NovaVeil_WARP: 单容器 Cloudflare WARP 代理, 同时提供 SOCKS5 和 HTTP 正向代理,
// 进程内池化多个 WARP 隧道, 每个隧道一个出口 IP. 控制 API 收到 429 回报后
// 淘汰对应隧道并后台轮换; 403 视为形态/身份信号, 不换出口.
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
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"NovaVeil_WARP/internal/httpproxy"
	"NovaVeil_WARP/internal/socks5"
	"NovaVeil_WARP/internal/warp"
)

const httpMaxConcurrent = 256

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
		cooldown      = flag.Duration("cooldown", getenvDuration("WARP_COOLDOWN", warp.DefaultEgressCooldown), "被惩罚的配额段重新可用前的等待时长, 负值表示不冷却")
		memLimit      = flag.String("mem-limit", getenv("WARP_MEM_LIMIT", "300MiB"), "进程内存上限, 如 300MiB; 0 表示不限制")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if *poolSize < 1 || *poolSize > warp.MaxPoolSize {
		logger.Error("invalid pool-size", "value", *poolSize, "max", warp.MaxPoolSize)
		os.Exit(1)
	}

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

	memBytes, err := parseMemoryLimit(*memLimit)
	if err != nil {
		logger.Error("invalid mem-limit", "err", err)
		os.Exit(1)
	}
	if memBytes > 0 {
		// 软上限留两成余量给非堆内存, 避免触到容器硬限被 OOM kill.
		softLimit := memBytes - memBytes/5
		debug.SetMemoryLimit(softLimit)
		logger.Info("memory limit set", "soft_mb", softLimit>>20, "hard_mb", memBytes>>20)
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
		EgressCooldown:      *cooldown,
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
			Dial:          httpproxy.DialFunc(dial),
			Timeout:       30 * time.Second,
			MaxConcurrent: httpMaxConcurrent,
		}
		go startHTTPProxy(ctx, *httpListen, proxy, logger)
	}
	go startControl(ctx, *controlListen, pool, tracker, logger)
	go startMemoryWatch(ctx, memBytes, logger)

	logger.Info("NovaVeil_WARP ready", "socks", *socksListen, "http", *httpListen, "control", *controlListen)
	<-ctx.Done()
	logger.Info("shutting down")
}

// makeDialFunc 返回代理拨号函数, 连接关闭时释放租约.
func makeDialFunc(pool *warp.Pool, tracker *recentTracker, logger *slog.Logger) socks5.DialFunc {
	return func(ctx context.Context, network, addr, username string) (net.Conn, error) {
		if slot, ok := warp.ParseSlotAccount(username); ok {
			conn, err := pool.DialSlot(ctx, slot, network, addr)
			if err != nil {
				return nil, err
			}
			if egress := conn.EgressAddr(); egress != "" {
				tracker.Record(egress)
			}
			return conn, nil
		}
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
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
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
	var probeMu sync.Mutex
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

	mux.HandleFunc("GET /slots", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pool.Slots())
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
		target := egress
		if egress != "" {
			if pool.PenalizeByEgress(egress, reason) {
				penalized = 1
			}
		} else {
			// 只淘汰最近出口, 避免 429 连坐
			latest := tracker.Latest()
			target = latest
			if latest != "" && pool.PenalizeByEgress(latest, reason) {
				penalized = 1
			}
		}

		logger.Info("penalize request", "egress", egress, "target", target, "penalized", penalized)
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
		case query.Has("all"):
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
		if !probeMu.TryLock() {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "probe already running", http.StatusServiceUnavailable)
			return
		}
		defer probeMu.Unlock()
		egress := strings.TrimSpace(r.URL.Query().Get("egress"))
		probeCtx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
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

const trackerCompactHead = 64

type recentTracker struct {
	mu      sync.Mutex
	entries []egressStamp
	head    int
	window  time.Duration
}

type egressStamp struct {
	addr string
	at   time.Time
}

func newRecentTracker(window time.Duration) *recentTracker {
	return &recentTracker{window: window}
}

func (rt *recentTracker) pruneLocked(now time.Time) {
	cutoff := now.Add(-rt.window)
	for rt.head < len(rt.entries) && !rt.entries[rt.head].at.After(cutoff) {
		rt.head++
	}
	if rt.head == len(rt.entries) {
		rt.entries = rt.entries[:0]
		rt.head = 0
		return
	}
	if rt.head >= trackerCompactHead && rt.head*2 >= len(rt.entries) {
		rt.entries = append(rt.entries[:0], rt.entries[rt.head:]...)
		rt.head = 0
	}
}

func (rt *recentTracker) Record(addr string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	now := time.Now()
	rt.entries = append(rt.entries, egressStamp{addr: addr, at: now})
	rt.pruneLocked(now)
}

func (rt *recentTracker) Recent() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.pruneLocked(time.Now())
	seen := make(map[string]bool)
	var result []string
	for _, e := range rt.entries[rt.head:] {
		if !seen[e.addr] {
			seen[e.addr] = true
			result = append(result, e.addr)
		}
	}
	return result
}

// Latest 返回窗口内最近一次拨号使用的出口.
func (rt *recentTracker) Latest() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.pruneLocked(time.Now())
	if len(rt.entries) == 0 {
		return ""
	}
	return rt.entries[len(rt.entries)-1].addr
}

// --- 内存上限 ---

// parseMemoryLimit 解析 "300MiB" / "512MB" / "1073741824" 形式的内存上限.
// 0 表示不限制; 非法输入与负数一律报错.
func parseMemoryLimit(value string) (int64, error) {
	trimmed := strings.ToUpper(strings.TrimSpace(value))
	if trimmed == "" {
		return 0, nil
	}
	multiplier := int64(1)
	for _, unit := range []struct {
		suffix string
		factor int64
	}{
		{"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10},
		{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10},
		{"B", 1},
	} {
		if strings.HasSuffix(trimmed, unit.suffix) {
			multiplier = unit.factor
			trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, unit.suffix))
			break
		}
	}
	size, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid memory limit %q", value)
	}
	if size < 0 {
		return 0, fmt.Errorf("memory limit must not be negative: %q", value)
	}
	if size > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("memory limit %q overflows int64", value)
	}
	return size * multiplier, nil
}

// startMemoryWatch 周期性检查进程内存, 超限只告警不自杀.
// 真正的硬约束由容器的 mem_limit 承担, 进程侧只保证 GC 及时回收.
func startMemoryWatch(ctx context.Context, limit int64, logger *slog.Logger) {
	if limit <= 0 {
		return
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var stats runtime.MemStats
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runtime.ReadMemStats(&stats)
			used := int64(stats.Sys)
			if used > limit {
				logger.Warn("WARP memory above limit", "used_mb", used>>20, "limit_mb", limit>>20)
			}
		}
	}
}

// --- 环境变量辅助 ---

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatalEnv(key, value string, err error) {
	fmt.Fprintf(os.Stderr, "invalid %s=%q: %v\n", key, value, err)
	os.Exit(1)
}

func getenvInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			fatalEnv(key, v, err)
		}
		return n
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			fatalEnv(key, v, err)
		}
		return d
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
	case "":
		return def
	default:
		fatalEnv(key, v, errors.New("not a boolean"))
		return def
	}
}
