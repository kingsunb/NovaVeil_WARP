package warp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	_ "time/tzdata"
	"unicode/utf8"
)

func newTestStore(t *testing.T) (*nodeStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warp-nodes.json")
	store, err := openNodeStore(path, "America/New_York")
	if err != nil {
		t.Fatalf("openNodeStore: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close node store: %v", err)
		}
	})
	return store, path
}

func testClock(t *testing.T) (time.Time, *time.Location) {
	t.Helper()
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("load zone: %v", err)
	}
	return time.Date(2026, 3, 2, 12, 0, 0, 0, loc), loc
}

func testRecord(prefix, egress string) nodeRecord {
	return nodeRecord{
		Prefix: prefix,
		Egress: egress,
		Stack:  StackIPv6,
		Reg: registration{
			ID:            "id-" + prefix,
			AddressV6:     egress + "/128",
			PeerPublicKey: "peer",
			Endpoints:     []string{egress + ":2408", "162.159.192.1:2408"},
		},
	}
}

func addTestNode(t *testing.T, store *nodeStore, index, successes int, now, used time.Time) (string, string) {
	t.Helper()
	prefix := fmt.Sprintf("2a09:bac5:4733:%x::/64", index)
	egress := fmt.Sprintf("2a09:bac5:4733:%x::1", index)
	store.put(testRecord(prefix, egress), now)
	for attempt := 0; attempt < successes; attempt++ {
		if !store.success(egress, now) {
			t.Fatalf("success(%s) did not hit", egress)
		}
	}
	if !used.IsZero() {
		store.claim(prefix, used)
	}
	return prefix, egress
}

func TestOpenNodeStoreDisabledAndZone(t *testing.T) {
	if store, err := openNodeStore("", ""); store != nil || err != nil {
		t.Fatalf("openNodeStore(\"\", \"\") = (%v,%v), want (nil,nil)", store, err)
	}
	path := filepath.Join(t.TempDir(), "nodes.json")
	store, err := openNodeStore(path, "")
	if err != nil {
		t.Fatalf("openNodeStore: %v", err)
	}
	if store.zone != "America/New_York" {
		t.Fatalf("zone = %q, want America/New_York", store.zone)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := openNodeStore(path, "Not/AZone"); err == nil {
		t.Fatal("invalid zone must fail")
	}
}

func TestNodeStoreDayBoundary(t *testing.T) {
	store, _ := newTestStore(t)
	_, loc := testClock(t)
	before := time.Date(2026, 3, 1, 23, 59, 59, 0, loc)
	after := time.Date(2026, 3, 2, 0, 0, 1, 0, loc)
	if got := store.day(before); got != "2026-03-01" {
		t.Fatalf("day before midnight = %q, want 2026-03-01", got)
	}
	if got := store.day(after); got != "2026-03-02" {
		t.Fatalf("day after midnight = %q, want 2026-03-02", got)
	}
	if store.day(before) == store.day(after) {
		t.Fatal("day must change across local midnight")
	}
}

func TestNodeStorePick(t *testing.T) {
	now, _ := testClock(t)
	store, _ := newTestStore(t)

	_, _ = addTestNode(t, store, 1, 2, now, now.AddDate(0, 0, -1))
	oldest, _ := addTestNode(t, store, 2, 2, now, now.AddDate(0, 0, -2))
	worn, _ := addTestNode(t, store, 3, 5, now, time.Time{})
	for attempt := 0; attempt < buildFailLimit; attempt++ {
		store.buildFail(worn, now)
	}
	_, _ = addTestNode(t, store, 4, 9, now, now)
	failed, _ := addTestNode(t, store, 5, 7, now, time.Time{})
	store.fail(failed, "HTTP 429", now)
	skipped, _ := addTestNode(t, store, 6, 3, now, time.Time{})
	// 无成功记录时仍让位于有成功记录的节点.
	_, _ = addTestNode(t, store, 7, 0, now, now.AddDate(0, 0, -30))

	picked, ok := store.pick(now, map[string]bool{skipped: true})
	if !ok {
		t.Fatal("pick found no node")
	}
	if picked.Prefix != oldest {
		t.Fatalf("picked %q, want oldest %q", picked.Prefix, oldest)
	}

	// 全部无成功记录时放宽到第二轮.
	fresh, _ := newTestStore(t)
	_, _ = addTestNode(t, fresh, 1, 0, now, now.AddDate(0, 0, -1))
	freshUnused, _ := addTestNode(t, fresh, 2, 0, now, time.Time{})
	picked, ok = fresh.pick(now, nil)
	if !ok || picked.Prefix != freshUnused {
		t.Fatalf("fallback pick = (%q,%v), want %q", picked.Prefix, ok, freshUnused)
	}

	empty, _ := newTestStore(t)
	if _, ok := empty.pick(now, nil); ok {
		t.Fatal("empty store must not pick")
	}
}

func TestNodeStorePickReturnsCopy(t *testing.T) {
	now, _ := testClock(t)
	store, _ := newTestStore(t)
	prefix, _ := addTestNode(t, store, 1, 1, now, time.Time{})

	picked, ok := store.pick(now, nil)
	if !ok {
		t.Fatal("pick found no node")
	}
	picked.Reg.Endpoints[0] = "mutated"
	picked.Success = 99
	store.mu.Lock()
	stored := store.nodes[prefix]
	internalEgress := stored.Reg.Endpoints[0]
	internalSuccess := stored.Success
	store.mu.Unlock()
	if internalEgress == "mutated" || internalSuccess != 1 {
		t.Fatalf("pick leaked internal state: endpoint %q success %d", internalEgress, internalSuccess)
	}
}

func TestNodeStorePutMerge(t *testing.T) {
	now, _ := testClock(t)
	created := now.AddDate(0, 0, -3)
	store, _ := newTestStore(t)
	const prefix = "2a09:bac5:4733:1::/64"

	first := testRecord(prefix, "2a09:bac5:4733:1::1")
	first.Success = 4
	first.Fail = 2
	first.BuildFail = 1
	first.LastFailDay = "2026-02-27"
	first.LastFailWhy = "HTTP 429"
	first.LastOKDay = "2026-02-28"
	first.LastUsedDay = "2026-03-01"
	first.Disabled = true
	first.CreatedAt = created
	store.put(first, created)

	second := testRecord(prefix, "2a09:bac5:4733:1::2")
	second.Stack = StackIPv4
	second.Source = "2001:db8::9"
	second.Reg = registration{ID: "renewed"}
	store.put(second, now)

	store.mu.Lock()
	merged := *store.nodes[prefix]
	store.mu.Unlock()
	if merged.Success != 4 || merged.Fail != 2 || merged.BuildFail != 1 {
		t.Fatalf("history = %d/%d/%d, want 4/2/1", merged.Success, merged.Fail, merged.BuildFail)
	}
	if merged.LastUsedDay != "2026-03-01" || merged.LastFailDay != "2026-02-27" || merged.LastOKDay != "2026-02-28" {
		t.Fatalf("last days not preserved: %+v", merged)
	}
	if !merged.Disabled {
		t.Fatal("disabled must be preserved on merge")
	}
	if !merged.CreatedAt.Equal(created) {
		t.Fatalf("created at = %s, want %s", merged.CreatedAt, created)
	}
	if !merged.UpdatedAt.Equal(now) {
		t.Fatalf("updated at = %s, want %s", merged.UpdatedAt, now)
	}
	if merged.Egress != "2a09:bac5:4733:1::2" || merged.Stack != StackIPv4 || merged.Source != "2001:db8::9" {
		t.Fatalf("refreshed fields = %+v", merged)
	}
	if merged.Reg.ID != "renewed" {
		t.Fatalf("registration id = %q, want renewed", merged.Reg.ID)
	}

	const other = "2a09:bac5:4733:2::/64"
	store.put(testRecord(other, "2a09:bac5:4733:2::1"), now)
	store.mu.Lock()
	fresh := *store.nodes[other]
	store.mu.Unlock()
	if !fresh.CreatedAt.Equal(now) || !fresh.UpdatedAt.Equal(now) {
		t.Fatalf("new node times = %s/%s, want %s", fresh.CreatedAt, fresh.UpdatedAt, now)
	}
}

func TestNodeStoreSuccessAndFail(t *testing.T) {
	now, _ := testClock(t)
	store, _ := newTestStore(t)
	const prefix = "2a09:bac5:4733:3::/64"
	const egress = "2a09:bac5:4733:3::1"
	store.put(testRecord(prefix, egress), now)

	if store.success("2a09:bac5:4733:3::2", now) {
		t.Fatal("success must ignore unknown egress")
	}
	if !store.success(egress, now) {
		t.Fatal("success must hit the stored egress")
	}
	store.mu.Lock()
	record := *store.nodes[prefix]
	store.mu.Unlock()
	if record.Success != 1 {
		t.Fatalf("success = %d, want 1", record.Success)
	}
	if record.LastOKDay != store.day(now) {
		t.Fatalf("last ok day = %q, want %q", record.LastOKDay, store.day(now))
	}

	store.fail(prefix, strings.Repeat("配额耗尽", 40), now)
	store.mu.Lock()
	record = *store.nodes[prefix]
	store.mu.Unlock()
	if record.Fail != 1 {
		t.Fatalf("fail = %d, want 1", record.Fail)
	}
	if record.LastFailDay != store.day(now) {
		t.Fatalf("last fail day = %q, want %q", record.LastFailDay, store.day(now))
	}
	if len(record.LastFailWhy) > failReasonLimit {
		t.Fatalf("reason length = %d, want <= %d", len(record.LastFailWhy), failReasonLimit)
	}
	if !utf8.ValidString(record.LastFailWhy) {
		t.Fatal("truncated reason is not valid UTF-8")
	}
	if _, ok := store.pick(now, nil); ok {
		t.Fatal("failed node must not be picked today")
	}
}

func TestNodeStoreBuildFailDisables(t *testing.T) {
	now, _ := testClock(t)
	store, _ := newTestStore(t)
	prefix, _ := addTestNode(t, store, 1, 0, now, time.Time{})

	store.buildFail(prefix, now)
	store.buildFail(prefix, now)
	store.mu.Lock()
	record := *store.nodes[prefix]
	store.mu.Unlock()
	if record.Disabled {
		t.Fatal("two build failures must not disable")
	}
	store.buildFail(prefix, now)
	store.mu.Lock()
	record = *store.nodes[prefix]
	store.mu.Unlock()
	if !record.Disabled || record.BuildFail != buildFailLimit {
		t.Fatalf("after three failures = %+v, want disabled", record)
	}

	// 成功一次即认为连续失败中断.
	const other = "2a09:bac5:4733:2::/64"
	const otherEgress = "2a09:bac5:4733:2::1"
	store.put(testRecord(other, otherEgress), now)
	store.buildFail(other, now)
	store.buildFail(other, now)
	if !store.success(otherEgress, now) {
		t.Fatal("success must hit the second node")
	}
	store.buildFail(other, now)
	store.buildFail(other, now)
	store.mu.Lock()
	record = *store.nodes[other]
	store.mu.Unlock()
	if record.Disabled {
		t.Fatal("success must reset consecutive build failures")
	}
}

func TestNodeStoreDrift(t *testing.T) {
	now, _ := testClock(t)
	store, _ := newTestStore(t)
	const oldPrefix = "2a09:bac5:4733:4::/64"
	const newPrefix = "2a09:bac5:4733:5::/64"
	store.put(testRecord(oldPrefix, "2a09:bac5:4733:4::1"), now)
	for attempt := 0; attempt < 3; attempt++ {
		store.success("2a09:bac5:4733:4::1", now)
	}
	store.claim(oldPrefix, now.AddDate(0, 0, -1))

	store.drift(oldPrefix, "2a09:bac5:4733:5::1", newPrefix, now)
	store.mu.Lock()
	_, oldExists := store.nodes[oldPrefix]
	moved := *store.nodes[newPrefix]
	store.mu.Unlock()
	if oldExists {
		t.Fatal("old prefix must be removed")
	}
	if moved.Success != 3 || moved.Egress != "2a09:bac5:4733:5::1" {
		t.Fatalf("moved record = %+v", moved)
	}
	if moved.LastUsedDay != store.day(now.AddDate(0, 0, -1)) {
		t.Fatalf("last used day = %q, want preserved", moved.LastUsedDay)
	}

	const thirdPrefix = "2a09:bac5:4733:6::/64"
	store.put(testRecord(thirdPrefix, "2a09:bac5:4733:6::1"), now)
	store.drift(thirdPrefix, "2a09:bac5:4733:5::9", newPrefix, now)
	store.mu.Lock()
	_, thirdExists := store.nodes[thirdPrefix]
	kept := *store.nodes[newPrefix]
	store.mu.Unlock()
	if thirdExists {
		t.Fatal("drift source must be removed")
	}
	if kept.Success != 3 || kept.Egress != "2a09:bac5:4733:5::1" {
		t.Fatalf("existing target overwritten: %+v", kept)
	}
}

func TestNodeStoreFlushRoundTrip(t *testing.T) {
	now, _ := testClock(t)
	store, path := newTestStore(t)
	prefix, egress := addTestNode(t, store, 7, 1, now, now)
	store.fail(prefix, "HTTP 429", now)
	second, _ := addTestNode(t, store, 8, 2, now, time.Time{})
	store.buildFail(second, now)
	store.buildFail(second, now)

	if err := store.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	var file nodeFile
	if err := json.Unmarshal(payload, &file); err != nil {
		t.Fatalf("decode store: %v", err)
	}
	if file.Version != nodeStoreVersion || len(file.Nodes) != 2 {
		t.Fatalf("file = version %d with %d nodes", file.Version, len(file.Nodes))
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file must not survive a flush")
	}

	reopened, err := openNodeStore(path, "America/New_York")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	reopened.mu.Lock()
	record, ok := reopened.nodes[prefix]
	if !ok {
		reopened.mu.Unlock()
		t.Fatalf("prefix %q missing after reopen", prefix)
	}
	loaded := *record
	reopened.mu.Unlock()
	if loaded.Egress != egress || loaded.Success != 1 || loaded.Fail != 1 {
		t.Fatalf("loaded record = %+v", loaded)
	}
	if loaded.LastFailWhy != "HTTP 429" || loaded.LastUsedDay != reopened.day(now) {
		t.Fatalf("loaded history = %+v", loaded)
	}
	if !loaded.CreatedAt.Equal(now) || !loaded.UpdatedAt.Equal(now) {
		t.Fatalf("loaded times = %s/%s", loaded.CreatedAt, loaded.UpdatedAt)
	}
	if len(loaded.Reg.Endpoints) != 2 || loaded.Reg.ID != "id-"+prefix {
		t.Fatalf("loaded registration = %+v", loaded.Reg)
	}
	if stats := reopened.stats(now); stats.Total != 2 || stats.Disabled != 0 {
		t.Fatalf("reopened stats = %+v", stats)
	}
}

func TestNodeStoreFlushCleanWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clean.json")
	store, err := openNodeStore(path, "America/New_York")
	if err != nil {
		t.Fatalf("openNodeStore: %v", err)
	}
	if err := store.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("clean flush created %s", path)
	}
}

func TestNodeStoreCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"nodes":[`), 0o644); err != nil {
		t.Fatalf("write broken store: %v", err)
	}
	if _, err := openNodeStore(path, "America/New_York"); err == nil {
		t.Fatal("corrupt store must return an error")
	}
}

func TestNodeStoreStats(t *testing.T) {
	now, _ := testClock(t)
	store, _ := newTestStore(t)
	_, _ = addTestNode(t, store, 1, 2, now, now)
	failed, _ := addTestNode(t, store, 2, 1, now, time.Time{})
	store.fail(failed, "HTTP 429", now)
	disabled, _ := addTestNode(t, store, 3, 4, now, time.Time{})
	for attempt := 0; attempt < buildFailLimit; attempt++ {
		store.buildFail(disabled, now)
	}
	_, _ = addTestNode(t, store, 4, 0, now, time.Time{})

	stats := store.stats(now)
	if !stats.Enabled || stats.Zone != "America/New_York" || stats.Day != store.day(now) {
		t.Fatalf("stats header = %+v", stats)
	}
	if stats.Total != 4 || stats.Good != 2 || stats.Available != 1 {
		t.Fatalf("stats counts = %+v", stats)
	}
	if stats.UsedToday != 1 || stats.FailedToday != 1 || stats.Disabled != 1 {
		t.Fatalf("stats today = %+v", stats)
	}
	views := store.views(0)
	if len(views) != 4 {
		t.Fatalf("views = %d, want 4", len(views))
	}
	if views[0].Prefix != disabled {
		t.Fatalf("views order first = %q, want %q", views[0].Prefix, disabled)
	}
	if limited := store.views(2); len(limited) != 2 {
		t.Fatalf("limited views = %d, want 2", len(limited))
	}
	for _, view := range views {
		if view.Prefix == "" || view.Stack != string(StackIPv6) {
			t.Fatalf("view = %+v", view)
		}
	}
}
