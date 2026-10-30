package warp

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestRotationBackoff(t *testing.T) {
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{0, 15 * time.Second},
		{1, 30 * time.Second},
		{2, 60 * time.Second},
		{3, 120 * time.Second},
		{4, 240 * time.Second},
		{5, 300 * time.Second},
		{10, 300 * time.Second},
	}
	for _, tc := range cases {
		if got := rotationBackoff(tc.failures); got != tc.want {
			t.Fatalf("rotationBackoff(%d) = %s, want %s", tc.failures, got, tc.want)
		}
	}
}

func TestPruneRotationTimes(t *testing.T) {
	now := time.Now()
	times := []time.Time{
		now.Add(-2 * time.Hour),
		now.Add(-30 * time.Minute),
		now,
	}
	want := []time.Time{times[1], times[2]}
	got := pruneRotationTimes(times, now, time.Hour)
	if len(got) != 2 || !got[0].Equal(want[0]) || !got[1].Equal(want[1]) {
		t.Fatalf("pruneRotationTimes = %v, want last two", got)
	}
}

func TestFullRekeyBudget(t *testing.T) {
	p := &Pool{}
	now := time.Now()
	for index := 0; index < maxFullRekeysPerHour; index++ {
		if !p.takeFullRekeyLocked(now) {
			t.Fatalf("rekey %d rejected before budget", index)
		}
	}
	if p.takeFullRekeyLocked(now) {
		t.Fatal("rekey accepted after hourly budget")
	}
	if !p.takeFullRekeyLocked(now.Add(time.Hour + time.Second)) {
		t.Fatal("rekey rejected after window reset")
	}
}

func TestRotationFailureBackoff(t *testing.T) {
	p := &Pool{rotationFailures: make(map[string]rotationFailure)}
	now := time.Now()
	if delay := p.recordRotationFailureLocked("2001:db8::/64", now); delay != 15*time.Second {
		t.Fatalf("first delay = %s, want 15s", delay)
	}
	if delay := p.recordRotationFailureLocked("2001:db8::/64", now); delay != 30*time.Second {
		t.Fatalf("second delay = %s, want 30s", delay)
	}
	failure := p.rotationFailures["2001:db8::/64"]
	if failure.count != 2 || !failure.until.Equal(now.Add(30*time.Second)) {
		t.Fatalf("failure = %+v", failure)
	}
	p.clearRotationFailureLocked("2001:db8::/64")
	if _, ok := p.rotationFailures["2001:db8::/64"]; ok {
		t.Fatal("failure not cleared")
	}
}

// TestEgressCooldownIsShort 锁定「不锁池」语义: 冷却是短 TTL, 到期即释放配额段.
func TestEgressCooldownIsShort(t *testing.T) {
	if DefaultEgressCooldown > 5*time.Minute {
		t.Fatalf("default cooldown %s too long, would empty the pool", DefaultEgressCooldown)
	}
	p := &Pool{cooling: map[string]time.Time{}}
	e := &exit{id: "e1", egress: netip.MustParseAddr("2001:db8:1:2::1")}
	p.cooling[e.egressKey()] = time.Now().Add(DefaultEgressCooldown)
	if until := p.coolingUntilLocked(e, time.Now()); until.IsZero() {
		t.Fatal("active cooling must be reported")
	}
	if until := p.coolingUntilLocked(e, time.Now().Add(DefaultEgressCooldown+time.Second)); !until.IsZero() {
		t.Fatalf("expired cooling still reported: %s", until)
	}
}

// TestNegativeCooldownDisablesLock 验证负冷却值表示段立即可用.
func TestNegativeCooldownDisablesLock(t *testing.T) {
	p := &Pool{cooldown: -time.Second, cooling: map[string]time.Time{}}
	e := &exit{id: "e1", egress: netip.MustParseAddr("2001:db8:1:2::1")}
	p.cooling[e.egressKey()] = time.Now().Add(p.cooldown)
	if until := p.coolingUntilLocked(e, time.Now()); !until.IsZero() {
		t.Fatalf("cooling still active until %s, want released", until)
	}
}

// TestDropIdleLockedEvictsSlotBoundExit 锁定池满时可挤位:
// 槽位会在 bindSlotsLocked 里重绑, 绑着槽位的空闲出口必须可淘汰.
func TestDropIdleLockedEvictsSlotBoundExit(t *testing.T) {
	p := &Pool{size: 1}
	bound := &exit{id: "bound", egress: netip.MustParseAddr("2001:db8:1:2::1"), pins: 1}
	p.slots = []slot{{exit: bound}}
	p.active = []*exit{bound}
	p.mu.Lock()
	got := p.dropIdleLocked(nil)
	p.mu.Unlock()
	if got != bound {
		t.Fatal("slot-bound idle exit must be evictable")
	}
}

func TestPenalizeRetiresImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bad := &exit{id: "bad", egress: netip.MustParseAddr("2001:db8:1:2::1"), refs: 1}
	p := &Pool{
		ctx:      ctx,
		active:   []*exit{bad},
		cooling:  make(map[string]time.Time),
		reserved: make(map[string]bool),
		changed:  make(chan struct{}),
	}
	p.penalize(bad, "test")
	p.wait.Wait()
	if !bad.retired || !bad.connsDone {
		t.Fatal("penalized exit must retire and close connections immediately")
	}
	if len(p.active) != 0 {
		t.Fatal("penalized exit must stay out of the active ring")
	}
}

func TestRotationBackoffKeepsExitRetired(t *testing.T) {
	old := &exit{id: "old", egress: netip.MustParseAddr("2001:db8:1:2::1"), penalized: true, retired: true}
	until := time.Now().Add(time.Minute)
	p := &Pool{
		ctx:             context.Background(),
		cooling:         map[string]time.Time{old.egressKey(): until},
		lastRotateStart: time.Now(),
		keyRotations:    make(map[string][]time.Time),
		rotationFailures: map[string]rotationFailure{
			old.egressKey(): {count: 1, until: until},
		},
	}
	p.rotate(old, "test")
	if len(p.active) != 0 || !old.penalized || !old.retired {
		t.Fatal("backoff must not restore a penalized exit")
	}
	if got := p.cooling[old.egressKey()]; !got.Equal(until) {
		t.Fatalf("cooling = %s, want %s", got, until)
	}
}

func TestEgressPrefix(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"203.0.113.7", "203.0.113.7/32"},
	}
	for _, tc := range cases {
		if got := egressPrefix(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Fatalf("egressPrefix(%s) = %q, want %q", tc.addr, got, tc.want)
		}
	}
	if got := egressPrefix(netip.Addr{}); got != "" {
		t.Fatalf("invalid prefix = %q, want empty", got)
	}
}

func TestSameEgressPrefix(t *testing.T) {
	same64a := netip.MustParseAddr("2001:db8:1:2::1")
	same64b := netip.MustParseAddr("2001:db8:1:2::ffff")
	other64 := netip.MustParseAddr("2001:db8:1:3::1")
	v4a := netip.MustParseAddr("203.0.113.7")
	v4b := netip.MustParseAddr("203.0.113.8")
	if !sameEgressPrefix(same64a, same64b) {
		t.Fatal("same /64 must match")
	}
	if sameEgressPrefix(same64a, other64) {
		t.Fatal("different /64 must not match")
	}
	if !sameEgressPrefix(v4a, v4a) {
		t.Fatal("same /32 must match")
	}
	if sameEgressPrefix(v4a, v4b) {
		t.Fatal("different /32 must not match")
	}
	if sameEgressPrefix(netip.Addr{}, same64a) {
		t.Fatal("invalid address must not match")
	}
}
