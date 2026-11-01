package warp

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

const (
	// createAttempts 是一次补池最多尝试的候选数.
	createAttempts = 4
	// restoreAttempts 是一次补池最多复用几个历史节点.
	restoreAttempts = 2
	// reviveBudget 是单个历史节点重建的时间预算.
	reviveBudget = 15 * time.Second
	// distinctEgressWindow 是每段保留的 /128 样本上限.
	distinctEgressWindow = 8
	// nodeFlushInterval 是节点库落盘间隔.
	nodeFlushInterval = 30 * time.Second
)

// PrefixStat 是单个配额段的观测值.
type PrefixStat struct {
	Prefix      string `json:"prefix"`
	Allocations int    `json:"allocations"`
	Distinct    int    `json:"distinct_egress"`
	Active      int    `json:"active"`
	Cooling     bool   `json:"cooling"`
	RateLimited int    `json:"rate_limited"`
	LastEgress  string `json:"last_egress,omitempty"`
}

// RotationStats 是轮换结果计数.
type RotationStats struct {
	Attempts     int `json:"attempts"`
	Restored     int `json:"restored"`
	Registered   int `json:"registered"`
	Rekeyed      int `json:"rekeyed"`
	SamePrefix   int `json:"same_prefix"`
	RejectedBusy int `json:"rejected_busy"`
	RestoreFail  int `json:"restore_failed"`
	Failed       int `json:"failed"`
	BudgetOut    int `json:"budget_exhausted"`
}

type rotationKind int

const (
	rotationAttempt rotationKind = iota
	rotationRestored
	rotationRegistered
	rotationRekeyed
	rotationSamePrefix
	rotationRejected
	rotationRestoreFail
	rotationFailed
	rotationBudget
)

type prefixCounter struct {
	allocations int
	rateLimited int
	lastEgress  string
	seen        map[string]bool
}

type prefixTracker struct {
	mu     sync.Mutex
	counts map[string]*prefixCounter
	rot    RotationStats
}

func newPrefixTracker() *prefixTracker {
	return &prefixTracker{counts: make(map[string]*prefixCounter)}
}

// allocate 记录一次候选出口落在某个段上.
func (t *prefixTracker) allocate(egress netip.Addr) {
	if t == nil || !egress.IsValid() {
		return
	}
	key := egressPrefix(egress)
	if key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	counter := t.counterLocked(key)
	counter.allocations++
	counter.lastEgress = egress.String()
	if !counter.seen[egress.String()] && len(counter.seen) < distinctEgressWindow {
		counter.seen[egress.String()] = true
	}
}

// rateLimited 记录该段返回过 429.
func (t *prefixTracker) rateLimited(prefix string) {
	if t == nil || prefix == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.counterLocked(prefix).rateLimited++
}

func (t *prefixTracker) counterLocked(prefix string) *prefixCounter {
	counter, ok := t.counts[prefix]
	if !ok {
		counter = &prefixCounter{seen: make(map[string]bool)}
		t.counts[prefix] = counter
	}
	return counter
}

// count 累加一次轮换结果.
func (t *prefixTracker) count(kind rotationKind) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	switch kind {
	case rotationAttempt:
		t.rot.Attempts++
	case rotationRestored:
		t.rot.Restored++
	case rotationRegistered:
		t.rot.Registered++
	case rotationRekeyed:
		t.rot.Rekeyed++
	case rotationSamePrefix:
		t.rot.SamePrefix++
	case rotationRejected:
		t.rot.RejectedBusy++
	case rotationRestoreFail:
		t.rot.RestoreFail++
	case rotationFailed:
		t.rot.Failed++
	case rotationBudget:
		t.rot.BudgetOut++
	}
}

// snapshot 合并累计计数与池内实时占用.
func (t *prefixTracker) snapshot(active map[string]int, cooling map[string]bool) []PrefixStat {
	if t == nil {
		stats := make([]PrefixStat, 0, len(active))
		for prefix, count := range active {
			stats = append(stats, PrefixStat{Prefix: prefix, Active: count, Cooling: cooling[prefix]})
		}
		sort.Slice(stats, func(i, j int) bool { return stats[i].Prefix < stats[j].Prefix })
		return stats
	}
	t.mu.Lock()
	stats := make([]PrefixStat, 0, len(t.counts))
	for prefix, counter := range t.counts {
		stats = append(stats, PrefixStat{
			Prefix:      prefix,
			Allocations: counter.allocations,
			Distinct:    len(counter.seen),
			RateLimited: counter.rateLimited,
			LastEgress:  counter.lastEgress,
		})
	}
	t.mu.Unlock()
	for index := range stats {
		stats[index].Active = active[stats[index].Prefix]
		stats[index].Cooling = cooling[stats[index].Prefix]
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].Prefix < stats[j].Prefix })
	return stats
}

// rotation 返回轮换计数.
func (t *prefixTracker) rotation() RotationStats {
	if t == nil {
		return RotationStats{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rot
}
