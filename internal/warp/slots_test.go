package warp

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestParseSlotAccount(t *testing.T) {
	cases := []struct {
		account string
		slot    int
		ok      bool
	}{
		{"warp-0", 0, true},
		{"warp-12", 12, true},
		{" warp-3 ", 3, true},
		{"warp--1", -1, true},
		{"warp-x", -1, true},
		{"warp-", -1, true},
		{"user", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		slot, ok := ParseSlotAccount(tc.account)
		if slot != tc.slot || ok != tc.ok {
			t.Fatalf("ParseSlotAccount(%q) = (%d,%v), want (%d,%v)", tc.account, slot, ok, tc.slot, tc.ok)
		}
	}
}

func TestSlotErrors(t *testing.T) {
	unknown := &SlotUnknownError{Slot: 7}
	if status, retry := unknown.ProxyStatus(); status != 407 || retry != 0 {
		t.Fatalf("unknown status = (%d,%s), want (407,0)", status, retry)
	}
	if reply := unknown.Socks5Reply(); reply != 0x02 {
		t.Fatalf("unknown reply = %#x, want 0x02", reply)
	}

	unavailable := &SlotUnavailableError{Slot: 7, State: SlotBusy, RetryAfter: 1500 * time.Millisecond}
	status, retry := unavailable.ProxyStatus()
	if status != 503 || retry != 1500*time.Millisecond {
		t.Fatalf("unavailable status = (%d,%s), want (503,1.5s)", status, retry)
	}
	if reply := unavailable.Socks5Reply(); reply != 0x02 {
		t.Fatalf("unavailable reply = %#x, want 0x02", reply)
	}

	short := &SlotUnavailableError{Slot: 7, State: SlotCooling, RetryAfter: 10 * time.Millisecond}
	if _, retry := short.ProxyStatus(); retry != time.Second {
		t.Fatalf("short retry = %s, want 1s", retry)
	}
}

func TestBindSlotsInitialGeneration(t *testing.T) {
	fresh := &exit{id: "fresh", egress: netip.MustParseAddr("2001:db8:1::1")}
	p := &Pool{size: 2, active: []*exit{fresh}, slots: make([]slot, 2)}
	releases := p.bindSlotsLocked()
	if len(releases) != 0 {
		t.Fatalf("initial releases = %d, want 0", len(releases))
	}
	if p.slots[0].exit != fresh || p.slots[0].generation != 1 {
		t.Fatalf("slot0 = %+v, want fresh generation 1", p.slots[0])
	}
	if p.slots[1].exit != nil || p.slots[1].generation != 0 {
		t.Fatalf("slot1 = %+v, want unbound", p.slots[1])
	}
	if p.pins != 1 {
		t.Fatalf("pins = %d, want 1", p.pins)
	}
	if fresh.refs != 0 || fresh.pins != 1 || !fresh.idle() {
		t.Fatalf("fresh refs = %d, pins = %d, want user-idle with one pin", fresh.refs, fresh.pins)
	}
}

func TestBindSlotsSwapKeepsOldUntilReleased(t *testing.T) {
	old := &exit{id: "old", egress: netip.MustParseAddr("2001:db8:1::1"), pins: 1, penalized: true}
	fresh := &exit{id: "fresh", egress: netip.MustParseAddr("2001:db8:2::1")}
	p := &Pool{
		size:   1,
		active: []*exit{fresh},
		slots:  []slot{{exit: old, generation: 1}},
		pins:   1,
	}
	releases := p.bindSlotsLocked()
	if p.slots[0].exit != fresh || p.slots[0].generation != 2 {
		t.Fatalf("slot0 = %+v, want fresh generation 2", p.slots[0])
	}
	if len(releases) != 1 || releases[0] != old {
		t.Fatalf("releases = %v, want old", releases)
	}
	if p.pins != 1 {
		t.Fatalf("pins = %d, want 1", p.pins)
	}
	if old.pins != 1 {
		t.Fatalf("old pins before release = %d, want 1", old.pins)
	}
	p.releaseExits(releases)
	if old.pins != 0 {
		t.Fatalf("old pins after release = %d, want 0", old.pins)
	}
	if fresh.refs != 0 || fresh.pins != 1 {
		t.Fatalf("fresh refs = %d, pins = %d, want 0 and 1", fresh.refs, fresh.pins)
	}
}

func TestBindSlotsUnbindReleasesPin(t *testing.T) {
	old := &exit{id: "old", egress: netip.MustParseAddr("2001:db8:1::1"), pins: 1, penalized: true}
	p := &Pool{size: 1, slots: []slot{{exit: old, generation: 1}}, pins: 1}
	releases := p.bindSlotsLocked()
	if p.slots[0].exit != nil {
		t.Fatalf("slot0 = %+v, want unbound", p.slots[0])
	}
	if p.pins != 0 {
		t.Fatalf("pins = %d, want 0", p.pins)
	}
	if len(releases) != 1 || releases[0] != old {
		t.Fatalf("releases = %v, want old", releases)
	}
	p.releaseExits(releases)
	if old.pins != 0 {
		t.Fatalf("old pins = %d, want 0", old.pins)
	}
}

func TestDialSlotFailureDoesNotPenalize(t *testing.T) {
	e := &exit{id: "target-error", egress: netip.MustParseAddr("2001:db8:1::1"), pins: 1}
	p := &Pool{
		size:    1,
		active:  []*exit{e},
		slots:   []slot{{exit: e, generation: 1}},
		pins:    1,
		cooling: make(map[string]time.Time),
	}
	conn, err := p.DialSlot(context.Background(), 0, "tcp", "203.0.113.1:443")
	if err == nil || conn != nil {
		t.Fatal("dial without a network must fail")
	}
	if len(p.active) != 1 || p.active[0] != e || e.penalized || len(p.cooling) != 0 {
		t.Fatal("target dial failure must not penalize the exit")
	}
	if e.refs != 0 || e.pins != 1 {
		t.Fatalf("refs = %d, pins = %d, want 0 and 1", e.refs, e.pins)
	}
}

func TestDesiredLockedCoversSlots(t *testing.T) {
	p := &Pool{size: 4, minSize: 1, slots: make([]slot, 4)}
	if got := p.desiredLocked(); got != 4 {
		t.Fatalf("desired = %d, want 4", got)
	}
	p.pins = 2
	if got := p.desiredLocked(); got != 4 {
		t.Fatalf("desired with pins = %d, want 4", got)
	}
}

func TestSlotViewStates(t *testing.T) {
	now := time.Now()
	e := &exit{id: "e", egress: netip.MustParseAddr("2001:db8:1::1")}
	p := &Pool{
		size:   1,
		active: []*exit{e},
		slots:  []slot{{exit: e, generation: 1}},
		pins:   1,
		cooling: map[string]time.Time{
			e.egressKey(): now.Add(time.Minute),
		},
	}
	view := p.slotViewLocked(0, now)
	if view.State != SlotCooling || view.CoolingUntil == "" || view.Prefix != "2001:db8:1::/64" {
		t.Fatalf("cooling view = %+v", view)
	}
	p.cooling = nil
	view = p.slotViewLocked(0, now)
	if view.State != SlotActive {
		t.Fatalf("active state = %s, want active", view.State)
	}
	p.slots[0].inFlight = 1
	view = p.slotViewLocked(0, now)
	if view.State != SlotBusy {
		t.Fatalf("busy state = %s, want busy", view.State)
	}
	p.slots[0].exit = nil
	view = p.slotViewLocked(0, now)
	if view.State != SlotUnknown {
		t.Fatalf("unknown state = %s, want unknown", view.State)
	}
}

func TestSlotViewUnknownWhenExitPenalized(t *testing.T) {
	e := &exit{id: "e", egress: netip.MustParseAddr("2001:db8:1::1"), penalized: true}
	p := &Pool{
		size:   1,
		active: []*exit{e},
		slots:  []slot{{exit: e, generation: 1}},
		pins:   1,
	}
	if view := p.slotViewLocked(0, time.Now()); view.State != SlotUnknown {
		t.Fatalf("state = %s, want unknown", view.State)
	}
}
