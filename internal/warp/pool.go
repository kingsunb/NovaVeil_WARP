package warp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const DefaultPoolSize = 2

const MaxPoolSize = 32

// DefaultMinSize 是默认池底: 1 个在岗 + 2 个备用.
const DefaultMinSize = 3

// DefaultEgressCooldown 是被惩罚的配额段重新可用前的等待时长.
// 冷却取短值: 换段成本远低于让池子空掉的成本.
// 早期实现对齐到下一个 UTC 0 点(最长 6 小时), 一次全池换桶就能把池封死.
const DefaultEgressCooldown = 60 * time.Second

// ipv4FallbackBudget 是 v6 失败后改用 v4 重建的时间预算.
const ipv4FallbackBudget = 60 * time.Second

// refillRetryDelay spaces out a failed registration attempt. A successful
// attempt is only limited by the registrar's own 12-second pacing.
const refillRetryDelay = 5 * time.Second

// ErrClosed is returned when a pool is used after Close. Callers use it to
// tell a retiring pool apart from a temporary capacity wait.
var ErrClosed = errors.New("WARP pool is closed")

type logger interface {
	Debugf(string, ...interface{})
	Infof(string, ...interface{})
	Warnf(string, ...interface{})
	Errorf(string, ...interface{})
}

// slogLogger adapts the structured logger used by the gateway to the short
// diagnostic messages this package emits at its own lifecycle boundaries.
type slogLogger struct {
	log *slog.Logger
}

func (l slogLogger) logf(level slog.Level, format string, args ...interface{}) {
	if l.log == nil {
		return
	}
	l.log.Log(context.Background(), level, fmt.Sprintf(format, args...), "component", "warp")
}

func (l slogLogger) Debugf(format string, args ...interface{}) {
	l.logf(slog.LevelDebug, format, args...)
}

func (l slogLogger) Infof(format string, args ...interface{}) {
	l.logf(slog.LevelInfo, format, args...)
}

func (l slogLogger) Warnf(format string, args ...interface{}) {
	l.logf(slog.LevelWarn, format, args...)
}

func (l slogLogger) Errorf(format string, args ...interface{}) {
	l.logf(slog.LevelError, format, args...)
}

type Pool struct {
	ctx     context.Context
	cancel  context.CancelFunc
	logger  logger
	size    int
	minSize int
	stack   Stack
	newExit func(context.Context) (*exit, error)

	mu        sync.Mutex
	active    []*exit
	inflight  int
	waiting   int
	next      int
	reserved  map[string]bool
	cooling   map[string]time.Time
	changed   chan struct{}
	closed    bool
	refilling bool
	wait      sync.WaitGroup
	createMu  sync.Mutex

	slots        []slot
	pins         int
	sourcePrefix netip.Prefix
	cooldown     time.Duration

	rotateMu         sync.Mutex
	lastRotateStart  time.Time
	keyRotations     map[string][]time.Time
	fullRekeys       []time.Time
	rotationFailures map[string]rotationFailure

	// nodes 是跨重启的出口节点库, 关闭时不落盘.
	nodes   *nodeStore
	tracker *prefixTracker
}

type Lease struct {
	pool *Pool
	exit *exit
	once sync.Once
}

// Snapshot is a point-in-time view of a pool for health and admin reporting.
type Snapshot struct {
	Stack string
	Size  int
	// MinSize 是空闲时也要保活的出口下限.
	MinSize int
	// Active is the number of exits currently in the ring. Standby counts the
	// idle part of it: exits not held by a lease and ready to replace a
	// penalized one immediately.
	Active  int
	Standby int
	Cooling int
	// Fallback 统计实际走 v4 的出口数, 非零说明 v6 不可用.
	Fallback int
	Egress   []string
}

// Options configure a WARP pool.
type Options struct {
	// Size is the fixed number of hot exits; every slot stays bound to one.
	Size int
	// MinSize 是空闲时也保活的出口下限, 小于 2 时按 2 处理.
	MinSize int
	// Stack selects the address family inside the tunnel. An IPv6 stack makes
	// the public egress an IPv6 address.
	Stack Stack
	// DisableIPv4Fallback 关闭 v6 建立失败后的 v4 兜底.
	// 零值即启用兜底, 避免调用方漏传导致静默关闭.
	DisableIPv4Fallback bool
	// SourceIPv6, when valid, is the outer IPv6 prefix each exit binds its
	// WireGuard socket to. Every exit draws its own address from it, so a
	// replacement reaches Cloudflare from a new source and receives a new
	// public egress — the only way past an egress-scoped free usage limit.
	SourceIPv6 netip.Prefix
	// EgressCooldown 是被惩罚的配额段再次可用前的等待时长.
	// 零值即用 DefaultEgressCooldown.
	EgressCooldown time.Duration
	// NodeDB 是节点库落盘路径, 空串表示不启用跨重启复用.
	NodeDB string
	// NodeZone 是节点库日界时区, 空串用美东.
	NodeZone string
}

// NewWithOptions creates a WARP pool whose exits use the selected IP stack and,
// optionally, rotate their outer IPv6 source within a prefix.
func NewWithOptions(ctx context.Context, log *slog.Logger, opts Options) (*Pool, error) {
	if opts.Size < 1 || opts.Size > MaxPoolSize {
		return nil, fmt.Errorf("WARP pool size must be between 1 and %d, got %d", MaxPoolSize, opts.Size)
	}
	normalized, err := ParseStack(string(opts.Stack))
	if err != nil {
		return nil, err
	}
	if opts.SourceIPv6.IsValid() && (!opts.SourceIPv6.Addr().Is6() || opts.SourceIPv6.Bits() > 64) {
		return nil, fmt.Errorf("WARP outer source must be an IPv6 prefix of /64 or shorter, got %s", opts.SourceIPv6)
	}
	size := opts.Size
	if size <= 0 {
		size = DefaultPoolSize
	}
	r := newRegistrar()
	store, storeErr := openNodeStore(opts.NodeDB, opts.NodeZone)
	if storeErr != nil {
		return nil, storeErr
	}
	pool, err := newPool(ctx, slogLogger{log: log}, size, opts.MinSize, store, func(ctx context.Context) (*exit, error) {
		reg, err := r.register(ctx)
		if err != nil {
			return nil, err
		}
		var source netip.Addr
		if opts.SourceIPv6.IsValid() {
			source, err = randomSource(opts.SourceIPv6)
			if err != nil {
				return nil, err
			}
		}
		candidate, err := newExitWithStack(ctx, reg, normalized, source)
		if err == nil || normalized != StackIPv6 || opts.DisableIPv4Fallback {
			return candidate, err
		}
		fallbackCtx, cancel := context.WithTimeout(ctx, ipv4FallbackBudget)
		defer cancel()
		if log != nil {
			log.Warn("WARP IPv6 exit unavailable, falling back to IPv4", "err", err)
		}
		// 同一份注册同时含 v4/v6 地址, 兜底无需重新注册.
		return newExitWithStack(fallbackCtx, reg, StackIPv4, netip.Addr{})
	})
	if err != nil {
		if store != nil {
			_ = store.Close()
		}
		return nil, err
	}
	pool.stack = normalized
	pool.sourcePrefix = opts.SourceIPv6
	pool.cooldown = opts.EgressCooldown
	if pool.cooldown == 0 {
		pool.cooldown = DefaultEgressCooldown
	}
	pool.startNodeFlush()
	return pool, nil
}

// randomSource draws one host address from prefix. The bits above the prefix
// length are kept, every bit below is random, so two exits practically never
// share an outer source.
func randomSource(prefix netip.Prefix) (netip.Addr, error) {
	address := prefix.Masked().Addr().As16()
	var noise [16]byte
	if _, err := rand.Read(noise[:]); err != nil {
		return netip.Addr{}, fmt.Errorf("draw WARP outer source: %w", err)
	}
	keep := prefix.Bits()
	for index := range address {
		switch bits := keep - index*8; {
		case bits >= 8:
		case bits <= 0:
			address[index] = noise[index]
		default:
			mask := byte(0xFF) << (8 - bits)
			address[index] = address[index]&mask | noise[index]&^mask
		}
	}
	return netip.AddrFrom16(address), nil
}

func newPool(ctx context.Context, log logger, size int, minSize int, store *nodeStore, create func(context.Context) (*exit, error)) (*Pool, error) {
	if size <= 0 {
		size = DefaultPoolSize
	}
	if minSize <= 0 {
		minSize = DefaultMinSize
	}
	if minSize < 2 {
		minSize = 2
	}
	if minSize > size {
		minSize = size
	}
	// The caller's context bounds the synchronous first registration, not the
	// pool: it is typically an initialization deadline that expires moments
	// after NewWithOptions returns. Deriving the pool lifetime from it would
	// cancel every later refill and replacement with "context canceled",
	// leaving the pool stuck on its first egress forever.
	poolCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	p := &Pool{
		ctx:              poolCtx,
		cancel:           cancel,
		logger:           log,
		size:             size,
		minSize:          minSize,
		newExit:          create,
		reserved:         make(map[string]bool),
		cooling:          make(map[string]time.Time),
		changed:          make(chan struct{}),
		slots:            make([]slot, size),
		keyRotations:     make(map[string][]time.Time),
		rotationFailures: make(map[string]rotationFailure),
		nodes:            store,
		tracker:          newPrefixTracker(),
	}
	first, err := p.createExit(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	p.active = []*exit{first}
	p.bindSlotsLocked()
	if log != nil {
		log.Infof("OpenCode WARP/%s pool ready (min %d, max %d exits)", first.stack, minSize, size)
	}
	p.startRefill()
	return p, nil
}

// 槽位数是池容量下限。
func (p *Pool) desiredLocked() int {
	want := p.inflight + p.waiting + p.pins + 1
	if want < len(p.slots) {
		want = len(p.slots)
	}
	if want < p.minSize {
		want = p.minSize
	}
	if want > p.size {
		want = p.size
	}
	return want
}

func (p *Pool) Acquire(ctx context.Context) (*Lease, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, ErrClosed
		}
		for attempts := 0; attempts < len(p.active); attempts++ {
			index := p.next % len(p.active)
			p.next = (p.next + 1) % len(p.active)
			active := p.active[index]
			if active.addRef() {
				p.inflight++
				p.mu.Unlock()
				// Demand just rose: grow the ring toward it in the background.
				p.startRefill()
				return &Lease{pool: p, exit: active}, nil
			}
		}
		p.waiting++
		changed := p.changed
		needRefill := len(p.active) < p.desiredLocked()
		p.mu.Unlock()
		if needRefill {
			// Queued demand is demand too: start growing before we block.
			p.startRefill()
		}
		var err error
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-p.ctx.Done():
			err = ErrClosed
		case <-changed:
		}
		p.mu.Lock()
		p.waiting--
		p.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
}

func (p *Pool) Report(lease *Lease, status int, body []byte) {
	if lease == nil || lease.exit == nil {
		return
	}
	rotate, reason := lease.exit.observe(status, body)
	if !rotate {
		return
	}
	p.penalize(lease.exit, reason)
}

// Fail drops an exit that cannot carry traffic even though the upstream never
// produced an HTTP response, such as a broken WARP handshake or a stalled first
// token. Retrying the same user-space tunnel would only repeat the stall.
func (p *Pool) Fail(lease *Lease, reason string) {
	if lease == nil || lease.exit == nil || reason == "" {
		return
	}
	p.penalize(lease.exit, reason)
}

func (p *Pool) Size() int { return p.size }

// PenalizeByEgress finds the active exit whose public egress matches addr and
// rotates it out. Returns false when no active exit has that egress. The caller
// (control API) passes the egress address that carried the rejected request.
func (p *Pool) PenalizeByEgress(addr string, reason string) bool {
	p.mu.Lock()
	var target *exit
	for _, active := range p.active {
		if active.egress.IsValid() && active.egress.String() == addr {
			target = active
			break
		}
	}
	p.mu.Unlock()
	if target == nil {
		return false
	}
	p.penalize(target, reason)
	return true
}

// PenalizeRecent rotates out every active exit whose egress key is in keys.
// Returns the count actually penalized. The control API uses this when the
// caller cannot pinpoint a single egress.
func (p *Pool) PenalizeRecent(keys []string, reason string) int {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	p.mu.Lock()
	var targets []*exit
	for _, active := range p.active {
		if active.egress.IsValid() && want[active.egress.String()] {
			targets = append(targets, active)
		}
	}
	p.mu.Unlock()
	for _, t := range targets {
		p.penalize(t, reason)
	}
	return len(targets)
}

// Snapshot reports the pool's current capacity and the public egress address
// of every active exit. It never exposes keys or device tokens.
func (p *Pool) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	snapshot := Snapshot{Stack: string(p.stack), Size: p.size, MinSize: p.minSize, Active: len(p.active), Cooling: len(p.cooling)}
	for _, active := range p.active {
		if active.idle() {
			snapshot.Standby++
		}
		if active.stack != p.stack {
			snapshot.Fallback++
		}
		if active.egress.IsValid() {
			snapshot.Egress = append(snapshot.Egress, active.egress.String())
		}
	}
	return snapshot
}

// CoolingUntil 返回冷却中的出口段及其解锁时刻.
func (p *Pool) CoolingUntil() map[string]time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	cooling := make(map[string]time.Time, len(p.cooling))
	for key, until := range p.cooling {
		cooling[key] = until
	}
	return cooling
}

// NodeStats 返回节点库汇总, 未启用时 Enabled 为 false.
func (p *Pool) NodeStats() NodeStats {
	if p.nodes == nil {
		return NodeStats{}
	}
	return p.nodes.stats(time.Now())
}

// NodeViews 返回脱敏节点列表.
func (p *Pool) NodeViews(limit int) []NodeView {
	if p.nodes == nil {
		return nil
	}
	return p.nodes.views(limit)
}

// MarkNodeSuccess 按完整出口记账成功.
func (p *Pool) MarkNodeSuccess(egress string) bool {
	if p.nodes == nil {
		return false
	}
	egress = strings.TrimSpace(egress)
	if egress == "" {
		return false
	}
	return p.nodes.success(egress, time.Now())
}

// MarkNodeFail 记录出口当天失败.
func (p *Pool) MarkNodeFail(egress, reason string) bool {
	if p.nodes == nil {
		return false
	}
	key := egressPrefixOf(egress)
	if key == "" {
		return false
	}
	if reason == "" {
		reason = "unknown"
	}
	p.nodes.fail(key, reason, time.Now())
	return true
}

// Prefixes 返回每段的分配数与限流计数.
func (p *Pool) Prefixes() []PrefixStat {
	p.mu.Lock()
	active := make(map[string]int, len(p.active))
	cooling := make(map[string]bool, len(p.cooling))
	now := time.Now()
	for _, item := range p.active {
		if key := item.egressKey(); key != "" {
			active[key]++
		}
	}
	for key, until := range p.cooling {
		if until.After(now) {
			cooling[key] = true
		}
	}
	p.mu.Unlock()
	return p.tracker.snapshot(active, cooling)
}

// Rotation 返回轮换与复用计数.
func (p *Pool) Rotation() RotationStats {
	return p.tracker.rotation()
}

func egressPrefixOf(value string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return egressPrefix(addr)
}

// startNodeFlush 周期落盘节点库.
func (p *Pool) startNodeFlush() {
	if p.nodes == nil {
		return
	}
	p.wait.Add(1)
	go func() {
		defer p.wait.Done()
		ticker := time.NewTicker(nodeFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
				if err := p.nodes.flush(); err != nil && p.logger != nil {
					p.logger.Warnf("Flush WARP node store: %v", err)
				}
			}
		}
	}()
}

// StartHealthCheck 启动周期巡检, interval 小于等于 0 时不启动.
func (p *Pool) StartHealthCheck(interval time.Duration) {
	if interval <= 0 {
		return
	}
	p.wait.Add(1)
	go func() {
		defer p.wait.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
				p.Check(p.ctx)
			}
		}
	}()
}

// Check 巡检全部空闲出口, 返回淘汰数量.
// 只探空闲出口, 避免打断正在传输的连接.
func (p *Pool) Check(ctx context.Context) int {
	p.mu.Lock()
	candidates := make([]*exit, 0, len(p.active))
	for _, active := range p.active {
		if active.idle() {
			candidates = append(candidates, active)
		}
	}
	p.mu.Unlock()
	dropped := 0
	for _, candidate := range candidates {
		egress, err := candidate.verifyEgress(ctx)
		if err == nil && egress == candidate.egress {
			continue
		}
		reason := "health check failed"
		if err == nil {
			reason = "egress drifted"
		}
		p.penalize(candidate, reason)
		dropped++
	}
	return dropped
}

// ProbeEgress 巡检指定出口, 返回健康状态与是否找到该出口.
// 探测失败或出口发生漂移时立即淘汰.
func (p *Pool) ProbeEgress(ctx context.Context, addr string) (bool, bool) {
	p.mu.Lock()
	var target *exit
	for _, active := range p.active {
		if active.egress.IsValid() && active.egress.String() == addr {
			target = active
			break
		}
	}
	p.mu.Unlock()
	if target == nil {
		return false, false
	}
	egress, err := target.verifyEgress(ctx)
	if err != nil {
		p.penalize(target, "probe failed")
		return false, true
	}
	if egress != target.egress {
		p.penalize(target, "egress drifted")
		return false, true
	}
	return true, true
}

// RotateAll 淘汰全部在岗出口, 返回淘汰数量.
func (p *Pool) RotateAll(reason string) int {
	p.mu.Lock()
	targets := append([]*exit(nil), p.active...)
	p.mu.Unlock()
	for _, target := range targets {
		p.penalize(target, reason)
	}
	return len(targets)
}

func (p *Pool) penalize(bad *exit, reason string) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	index := p.activeIndexLocked(bad)
	if index < 0 {
		p.mu.Unlock()
		return
	}
	if !bad.markPenalized() {
		p.mu.Unlock()
		return
	}
	if key := bad.egressKey(); key != "" {
		p.cooling[key] = time.Now().Add(p.cooldown)
		delete(p.reserved, key)
		if p.nodes != nil {
			// 429 只让节点今天歇着, 凭据留着明天再用.
			p.nodes.fail(key, reason, time.Now())
		}
		if strings.Contains(reason, "429") {
			p.tracker.rateLimited(key)
		}
	}
	p.active = append(p.active[:index], p.active[index+1:]...)
	if p.next >= len(p.active) {
		p.next = 0
	}
	releases := p.bindSlotsLocked()
	p.notifyLocked()
	p.wait.Add(1)
	p.mu.Unlock()

	bad.retire()
	p.releaseExits(releases)
	if p.logger != nil {
		p.logger.Warnf("Rotating OpenCode WARP egress %s (%s)", bad.id, reason)
	}
	// Re-register immediately: the retired exit is replaced in the background
	// and the retry draws whichever active exit is ready first.
	go func() {
		defer p.wait.Done()
		p.rotate(bad, reason)
	}()
}

func (p *Pool) refill() {
	p.mu.Lock()
	if p.closed || p.refilling || !p.needsRefillLocked() {
		p.mu.Unlock()
		return
	}
	p.refilling = true
	p.mu.Unlock()

	replacement, err := p.createExit(p.ctx)
	p.mu.Lock()
	p.refilling = false
	placed := false
	var releases []*exit
	if err == nil && !p.closed && len(p.active) < p.size {
		p.active = append(p.active, replacement)
		replacement = nil
		placed = true
		releases = p.bindSlotsLocked()
	}
	if placed || p.closed {
		p.notifyLocked()
	}
	p.mu.Unlock()

	p.releaseExits(releases)
	if replacement != nil {
		p.releaseReservation(replacement)
		replacement.close()
	}
	if err != nil && p.ctx.Err() == nil {
		if p.logger != nil {
			p.logger.Warnf("Cannot pre-register OpenCode WARP egress: %v", err)
		}
		// Every registration is already paced by the registrar; retry soon
		// instead of leaving the pool under its target for a long window.
		p.after(refillRetryDelay, p.startRefill)
		return
	}
	p.startRefill()
}

func (p *Pool) startRefill() {
	p.mu.Lock()
	if p.closed || p.refilling || !p.needsRefillLocked() {
		p.mu.Unlock()
		return
	}
	p.wait.Add(1)
	p.mu.Unlock()
	go func() {
		defer p.wait.Done()
		p.refill()
	}()
}

// released records that a lease was returned and refills below the slot target.
func (p *Pool) released() {
	p.mu.Lock()
	if p.inflight > 0 {
		p.inflight--
	}
	closed := p.closed
	wantRefill := !closed && len(p.active) < p.desiredLocked()
	p.mu.Unlock()
	if closed {
		return
	}
	if wantRefill {
		p.startRefill()
	}
}

// after runs fn once delay has elapsed, unless the pool closes first.
func (p *Pool) after(delay time.Duration, fn func()) {
	p.wait.Add(1)
	go func() {
		defer p.wait.Done()
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
		case <-timer.C:
			fn()
		}
	}()
}

// createExit 取一个可入池的出口: 先复用历史节点, 再注册新设备.
func (p *Pool) createExit(ctx context.Context) (*exit, error) {
	p.createMu.Lock()
	defer p.createMu.Unlock()
	var lastErr error
	for attempt := 0; attempt < createAttempts; attempt++ {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return nil, ErrClosed
		}
		candidate, err := p.nextExit(ctx)
		if err != nil {
			return nil, err
		}
		key := candidate.egressKey()
		if p.reserveKey(key) {
			p.recordNode(candidate)
			if p.nodes != nil {
				p.nodes.claim(key, time.Now())
			}
			if p.logger != nil {
				p.logger.Infof("OpenCode WARP/%s egress %s ready at %s", candidate.stack, candidate.id, candidate.egress)
			}
			return candidate, nil
		}
		lastErr = fmt.Errorf("WARP egress %s is already active or cooling down", key)
		p.tracker.count(rotationRejected)
		if p.logger != nil {
			p.logger.Warnf("Discarding duplicate WARP exit %s: %v", candidate.id, lastErr)
		}
		// 撞段不丢注册, 留作后续日界复用.
		p.keepNode(candidate)
		candidate.close()
	}
	return nil, lastErr
}

// nextExit 优先复用节点库, 没有可复用节点才注册.
func (p *Pool) nextExit(ctx context.Context) (*exit, error) {
	if p.nodes != nil {
		skip := p.busyPrefixes()
		for restored := 0; restored < restoreAttempts; restored++ {
			record, ok := p.nodes.pick(time.Now(), skip)
			if !ok {
				break
			}
			skip[record.Prefix] = true
			candidate, err := p.reviveExit(ctx, record)
			if err != nil {
				p.tracker.count(rotationRestoreFail)
				if p.logger != nil {
					p.logger.Warnf("Cannot revive WARP node %s (%s): %v", record.Prefix, record.Egress, err)
				}
				continue
			}
			p.tracker.count(rotationRestored)
			p.tracker.allocate(candidate.egress)
			return candidate, nil
		}
	}
	p.tracker.count(rotationRegistered)
	candidate, err := p.newExit(ctx)
	if err != nil {
		return nil, err
	}
	p.tracker.allocate(candidate.egress)
	return candidate, nil
}

// reviveExit 用库里注册重建隧道, 段漂移时按新段记账.
func (p *Pool) reviveExit(ctx context.Context, record nodeRecord) (*exit, error) {
	var source netip.Addr
	if record.Source != "" {
		parsed, err := netip.ParseAddr(record.Source)
		if err != nil {
			p.nodes.buildFail(record.Prefix, time.Now())
			return nil, fmt.Errorf("invalid WARP node source %q: %w", record.Source, err)
		}
		source = parsed
	}
	// 失效注册可能在探活上耗很久, 单次重建设预算.
	reviveCtx, cancel := context.WithTimeout(ctx, reviveBudget)
	defer cancel()
	candidate, err := newExitWithStack(reviveCtx, record.Reg, record.Stack, source)
	if err != nil {
		p.nodes.buildFail(record.Prefix, time.Now())
		return nil, err
	}
	if observed := candidate.egressKey(); observed != "" && observed != record.Prefix {
		if p.logger != nil {
			p.logger.Warnf("WARP node %s came back on %s", record.Prefix, observed)
		}
		p.nodes.drift(record.Prefix, candidate.egress.String(), observed, time.Now())
	}
	return candidate, nil
}

// reserveKey 尝试占用配额段, 已占用或冷却中返回 false.
func (p *Pool) reserveKey(key string) bool {
	if key == "" {
		return false
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for subnet, until := range p.cooling {
		if !until.After(now) {
			delete(p.cooling, subnet)
		}
	}
	if p.reserved[key] || p.cooling[key].After(now) {
		return false
	}
	p.reserved[key] = true
	return true
}

// busyPrefixes 返回当前不可复用的配额段.
func (p *Pool) busyPrefixes() map[string]bool {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	busy := make(map[string]bool, len(p.reserved)+len(p.cooling))
	for key := range p.reserved {
		busy[key] = true
	}
	for key, until := range p.cooling {
		if until.After(now) {
			busy[key] = true
		}
	}
	return busy
}

// recordNode 把成功入池的出口写回节点库.
func (p *Pool) recordNode(candidate *exit) {
	if p.nodes == nil || candidate == nil || !candidate.egress.IsValid() {
		return
	}
	key := candidate.egressKey()
	if key == "" {
		return
	}
	p.nodes.put(nodeRecord{
		Prefix: key,
		Egress: candidate.egress.String(),
		Stack:  candidate.stack,
		Source: sourceString(candidate.source),
		Reg:    candidate.reg,
	}, time.Now())
}

// keepNode 保留撞段候选的注册, 已有该段记录时不覆盖.
func (p *Pool) keepNode(candidate *exit) {
	if p.nodes == nil || candidate == nil || !candidate.egress.IsValid() {
		return
	}
	if key := candidate.egressKey(); key == "" || p.nodes.has(key) {
		return
	}
	p.recordNode(candidate)
}

func sourceString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func (p *Pool) releaseReservation(e *exit) {
	if e == nil {
		return
	}
	key := e.egressKey()
	if key == "" {
		return
	}
	p.mu.Lock()
	delete(p.reserved, key)
	p.mu.Unlock()
}

func (p *Pool) notifyLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *Pool) activeIndexLocked(target *exit) int {
	for index, candidate := range p.active {
		if candidate == target {
			return index
		}
	}
	return -1
}

func (p *Pool) needsRefillLocked() bool {
	return len(p.active) < p.desiredLocked()
}

func (p *Pool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	active := p.active
	p.active = nil
	slotExits := make([]*exit, 0, len(p.slots))
	for index := range p.slots {
		if p.slots[index].exit != nil {
			slotExits = append(slotExits, p.slots[index].exit)
			p.slots[index].exit = nil
		}
	}
	p.pins = 0
	p.notifyLocked()
	p.mu.Unlock()

	p.cancel()
	for _, item := range slotExits {
		item.releasePin()
	}
	for _, item := range active {
		p.releaseReservation(item)
		item.retire()
	}
	p.wait.Wait()
	if p.nodes != nil {
		if err := p.nodes.Close(); err != nil && p.logger != nil {
			p.logger.Warnf("Close WARP node store: %v", err)
		}
	}
}

func (l *Lease) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if l == nil || l.exit == nil {
		return nil, errors.New("WARP lease is closed")
	}
	return l.exit.dialContext(ctx, network, address)
}

func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.exit != nil {
			l.exit.release()
		}
		if l.pool != nil {
			l.pool.released()
		}
	})
}

func (l *Lease) EgressKey() string {
	if l == nil || l.exit == nil {
		return ""
	}
	return l.exit.egressKey()
}

// EgressAddr 返回该租约出口的完整公网地址字符串, 供控制 API 精确惩罚.
func (l *Lease) EgressAddr() string {
	if l == nil || l.exit == nil || !l.exit.egress.IsValid() {
		return ""
	}
	return l.exit.egress.String()
}

// DialNetwork is the explicit TCP address family for this lease. Callers should
// pass it to DialContext instead of assuming IPv6.
func (l *Lease) DialNetwork() string {
	if l == nil || l.exit == nil {
		return ""
	}
	return l.exit.dialNetwork()
}

func (l *Lease) String() string {
	if l == nil || l.exit == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s/%s", l.exit.id, l.exit.egress)
}
