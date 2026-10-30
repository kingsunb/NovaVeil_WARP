package warp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SlotAccountPrefix 是槽位账号的固定前缀.
const SlotAccountPrefix = "warp-"

// SlotState 是槽位对外状态.
type SlotState string

const (
	SlotActive  SlotState = "active"
	SlotBusy    SlotState = "busy"
	SlotCooling SlotState = "cooling"
	SlotUnknown SlotState = "unknown"
)

// SlotView 是 GET /slots 返回的单个槽位.
type SlotView struct {
	Slot         int       `json:"slot"`
	Account      string    `json:"account"`
	Egress       string    `json:"egress"`
	Prefix       string    `json:"prefix"`
	State        SlotState `json:"state"`
	InFlight     int       `json:"in_flight"`
	CoolingUntil string    `json:"cooling_until"`
	Generation   int       `json:"generation"`
}

// SlotsSnapshot 是槽位表的点时刻快照.
type SlotsSnapshot struct {
	Size      int        `json:"size"`
	UpdatedAt string     `json:"updated_at"`
	Slots     []SlotView `json:"slots"`
}

type slot struct {
	exit       *exit
	generation int
	inFlight   int
}

// ParseSlotAccount 解析 warp-<slot> 账号.
// 第二个返回值表示账号是否带 warp- 前缀.
func ParseSlotAccount(account string) (int, bool) {
	account = strings.TrimSpace(account)
	if !strings.HasPrefix(account, SlotAccountPrefix) {
		return 0, false
	}
	raw := strings.TrimPrefix(account, SlotAccountPrefix)
	slot, err := strconv.Atoi(raw)
	if err != nil || slot < 0 {
		return -1, true
	}
	return slot, true
}

// SlotUnknownError 表示槽位号不存在.
type SlotUnknownError struct {
	Slot int
}

func (e *SlotUnknownError) Error() string {
	return fmt.Sprintf("WARP slot %d does not exist", e.Slot)
}

// ProxyStatus 让 HTTP 代理返回 407.
func (e *SlotUnknownError) ProxyStatus() (int, time.Duration) {
	return 407, 0
}

// Socks5Reply 把未知槽位映射为规则拒绝.
func (e *SlotUnknownError) Socks5Reply() byte {
	return 0x02
}

// SlotUnavailableError 表示槽位忙、冷却或暂无出口.
type SlotUnavailableError struct {
	Slot       int
	State      SlotState
	RetryAfter time.Duration
}

func (e *SlotUnavailableError) Error() string {
	return fmt.Sprintf("WARP slot %d is %s", e.Slot, e.State)
}

// ProxyStatus 让 HTTP 代理返回 503 与 Retry-After.
func (e *SlotUnavailableError) ProxyStatus() (int, time.Duration) {
	delay := e.RetryAfter
	if delay < time.Second {
		delay = time.Second
	}
	return 503, delay
}

// Socks5Reply 把不可用槽位映射为规则拒绝.
func (e *SlotUnavailableError) Socks5Reply() byte {
	return 0x02
}

// Slots 返回槽位表快照.
func (p *Pool) Slots() SlotsSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	snapshot := SlotsSnapshot{
		Size:      p.size,
		UpdatedAt: now.UTC().Format(time.RFC3339),
		Slots:     make([]SlotView, 0, len(p.slots)),
	}
	for index := range p.slots {
		snapshot.Slots = append(snapshot.Slots, p.slotViewLocked(index, now))
	}
	return snapshot
}

func (p *Pool) slotViewLocked(index int, now time.Time) SlotView {
	s := &p.slots[index]
	view := SlotView{
		Slot:       index,
		Account:    SlotAccountPrefix + strconv.Itoa(index),
		InFlight:   s.inFlight,
		Generation: s.generation,
	}
	if s.exit == nil {
		view.State = SlotUnknown
		return view
	}
	if s.exit.egress.IsValid() {
		view.Egress = s.exit.egress.String()
	}
	view.Prefix = s.exit.egressKey()
	if until := p.coolingUntilLocked(s.exit, now); !until.IsZero() {
		view.State = SlotCooling
		view.CoolingUntil = until.UTC().Format(time.RFC3339)
		return view
	}
	if !s.exit.available() || p.activeIndexLocked(s.exit) < 0 {
		view.State = SlotUnknown
		return view
	}
	if s.inFlight > 0 {
		view.State = SlotBusy
		return view
	}
	view.State = SlotActive
	return view
}

func (p *Pool) coolingUntilLocked(e *exit, now time.Time) time.Time {
	if e == nil {
		return time.Time{}
	}
	key := e.egressKey()
	if key == "" {
		return time.Time{}
	}
	until := p.cooling[key]
	if until.After(now) {
		return until
	}
	return time.Time{}
}

// bindSlotsLocked 给空闲槽位绑定未被占用的出口.
// 返回需要延迟释放的旧出口.
func (p *Pool) bindSlotsLocked() []*exit {
	used := make(map[*exit]bool, len(p.slots))
	for index := range p.slots {
		s := &p.slots[index]
		if s.exit != nil && p.activeIndexLocked(s.exit) >= 0 && s.exit.available() {
			used[s.exit] = true
		}
	}
	var releases []*exit
	for index := range p.slots {
		s := &p.slots[index]
		if s.exit != nil && used[s.exit] {
			continue
		}
		var candidate *exit
		for _, e := range p.active {
			if used[e] || !e.available() || !e.addRef() {
				continue
			}
			candidate = e
			break
		}
		if candidate == nil {
			if s.exit != nil {
				releases = append(releases, s.exit)
				s.exit = nil
				// 解绑槽位归还钉住计数。
				p.pins--
			}
			continue
		}
		old := s.exit
		s.exit = candidate
		if s.generation == 0 {
			s.generation = 1
		} else {
			s.generation++
		}
		if old == nil {
			p.pins++
		} else {
			releases = append(releases, old)
		}
		used[candidate] = true
	}
	return releases
}

func (p *Pool) slotBoundLocked(e *exit) bool {
	for index := range p.slots {
		if p.slots[index].exit == e {
			return true
		}
	}
	return false
}

func (p *Pool) releaseExits(exits []*exit) {
	for _, e := range exits {
		e.release()
	}
}

type slotLease struct {
	pool *Pool
	slot int
	exit *exit
	once sync.Once
}

func (l *slotLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.pool.mu.Lock()
		if l.slot >= 0 && l.slot < len(l.pool.slots) && l.pool.slots[l.slot].inFlight > 0 {
			l.pool.slots[l.slot].inFlight--
		}
		l.pool.mu.Unlock()
		if l.exit != nil {
			l.exit.release()
		}
	})
}

// DialSlot 通过指定槽位拨号, 单槽位串行.
func (p *Pool) DialSlot(ctx context.Context, slot int, network, address string) (*SlotConn, error) {
	lease, err := p.acquireSlot(slot)
	if err != nil {
		return nil, err
	}
	dialNetwork := lease.exit.dialNetwork()
	if dialNetwork == "" {
		dialNetwork = network
	}
	conn, err := lease.exit.dialContext(ctx, dialNetwork, address)
	if err != nil {
		if ctx.Err() == nil {
			p.penalize(lease.exit, err.Error())
		}
		lease.Release()
		return nil, err
	}
	return &SlotConn{Conn: conn, lease: lease}, nil
}

func (p *Pool) acquireSlot(slot int) (*slotLease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrClosed
	}
	if slot < 0 || slot >= len(p.slots) {
		return nil, &SlotUnknownError{Slot: slot}
	}
	now := time.Now()
	s := &p.slots[slot]
	if s.exit == nil {
		return nil, &SlotUnavailableError{Slot: slot, State: SlotUnknown, RetryAfter: time.Second}
	}
	if until := p.coolingUntilLocked(s.exit, now); !until.IsZero() {
		return nil, &SlotUnavailableError{Slot: slot, State: SlotCooling, RetryAfter: until.Sub(now)}
	}
	if !s.exit.available() || p.activeIndexLocked(s.exit) < 0 {
		return nil, &SlotUnavailableError{Slot: slot, State: SlotUnknown, RetryAfter: time.Second}
	}
	if s.inFlight > 0 {
		return nil, &SlotUnavailableError{Slot: slot, State: SlotBusy, RetryAfter: time.Second}
	}
	if !s.exit.addRef() {
		return nil, &SlotUnavailableError{Slot: slot, State: SlotUnknown, RetryAfter: time.Second}
	}
	s.inFlight++
	return &slotLease{pool: p, slot: slot, exit: s.exit}, nil
}

// SlotConn 关闭时归还槽位.
type SlotConn struct {
	net.Conn
	lease *slotLease
}

func (c *SlotConn) Close() error {
	err := c.Conn.Close()
	if c.lease != nil {
		c.lease.Release()
	}
	return err
}

func (c *SlotConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// EgressAddr 返回该连接所用出口的公网地址.
func (c *SlotConn) EgressAddr() string {
	if c == nil || c.lease == nil || c.lease.exit == nil || !c.lease.exit.egress.IsValid() {
		return ""
	}
	return c.lease.exit.egress.String()
}
