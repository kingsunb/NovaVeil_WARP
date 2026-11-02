package warp

import (
	"testing"
	"time"
)

func TestPenaltyStateThreshold(t *testing.T) {
	const egress = "203.0.113.7"
	pool := &Pool{penaltyStrikes: map[string]int{egress: sameEgressPenaltyLimit - 1}}

	strikes, hit := pool.PenaltyState(egress)
	if hit || strikes != sameEgressPenaltyLimit-1 {
		t.Fatalf("阈值前 strikes=%d hit=%v", strikes, hit)
	}

	pool.penaltyStrikes[egress]++
	strikes, hit = pool.PenaltyState(egress)
	if !hit || strikes != sameEgressPenaltyLimit {
		t.Fatalf("阈值后 strikes=%d hit=%v", strikes, hit)
	}
}

func TestPenaltyStateUnknownEgress(t *testing.T) {
	pool := &Pool{}
	strikes, hit := pool.PenaltyState("203.0.113.8")
	if strikes != 0 || hit {
		t.Fatalf("未知出口 strikes=%d hit=%v", strikes, hit)
	}
}

func TestPenaltyStateResetsAfterUTC(t *testing.T) {
	const egress = "203.0.113.9"
	pool := &Pool{
		penaltyStrikes: map[string]int{egress: sameEgressPenaltyLimit},
		penaltyResetAt: time.Now().Add(-time.Second),
	}

	strikes, hit := pool.PenaltyState(egress)
	if strikes != 0 || hit {
		t.Fatalf("跨日后 strikes=%d hit=%v", strikes, hit)
	}
	if pool.penaltyStrikes != nil {
		t.Fatal("跨日后计数未清零")
	}
}
