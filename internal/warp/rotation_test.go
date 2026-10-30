package warp

import (
	"net/netip"
	"testing"
	"time"
)

func TestRotationBackoff(t *testing.T) {
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{0, 300 * time.Second},
		{1, 600 * time.Second},
		{2, 1200 * time.Second},
		{3, 2400 * time.Second},
		{4, 3600 * time.Second},
		{10, 3600 * time.Second},
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
	if delay := p.recordRotationFailureLocked("2001:db8::/64", now); delay != 300*time.Second {
		t.Fatalf("first delay = %s, want 300s", delay)
	}
	if delay := p.recordRotationFailureLocked("2001:db8::/64", now); delay != 600*time.Second {
		t.Fatalf("second delay = %s, want 600s", delay)
	}
	failure := p.rotationFailures["2001:db8::/64"]
	if failure.count != 2 || !failure.until.Equal(now.Add(600*time.Second)) {
		t.Fatalf("failure = %+v", failure)
	}
	p.clearRotationFailureLocked("2001:db8::/64")
	if _, ok := p.rotationFailures["2001:db8::/64"]; ok {
		t.Fatal("failure not cleared")
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
