package main

import (
	"reflect"
	"testing"
	"time"
)

func TestRecentTrackerLatest(t *testing.T) {
	rt := newRecentTracker(time.Minute)
	now := time.Now()
	rt.entries = []egressStamp{
		{addr: "a", at: now.Add(-3 * time.Second)},
		{addr: "b", at: now.Add(-2 * time.Second)},
		{addr: "a", at: now.Add(-time.Second)},
	}
	if got := rt.Latest(); got != "a" {
		t.Fatalf("Latest() = %q, want %q", got, "a")
	}
}

func TestRecentTrackerLatestSkipsExpired(t *testing.T) {
	rt := newRecentTracker(time.Minute)
	now := time.Now()
	rt.entries = []egressStamp{
		{addr: "old", at: now.Add(-2 * time.Minute)},
		{addr: "expired", at: now.Add(-time.Minute - time.Second)},
		{addr: "fresh", at: now.Add(-time.Second)},
	}
	if got := rt.Latest(); got != "fresh" {
		t.Fatalf("Latest() = %q, want %q", got, "fresh")
	}
}

func TestRecentTrackerLatestEmpty(t *testing.T) {
	rt := newRecentTracker(time.Minute)
	if got := rt.Latest(); got != "" {
		t.Fatalf("Latest() = %q, want empty", got)
	}
}

func TestRecentTrackerRecentDedupes(t *testing.T) {
	rt := newRecentTracker(time.Minute)
	now := time.Now()
	rt.entries = []egressStamp{
		{addr: "a", at: now.Add(-3 * time.Second)},
		{addr: "b", at: now.Add(-2 * time.Second)},
		{addr: "a", at: now.Add(-time.Second)},
	}
	want := []string{"a", "b"}
	if got := rt.Recent(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Recent() = %v, want %v", got, want)
	}
}

func TestRecentTrackerRecordCompacts(t *testing.T) {
	rt := newRecentTracker(time.Minute)
	now := time.Now()
	for index := 0; index < 100; index++ {
		rt.entries = append(rt.entries, egressStamp{addr: "old", at: now.Add(-2 * time.Minute)})
	}
	rt.Record("fresh")
	if rt.head != 0 || len(rt.entries) != 1 {
		t.Fatalf("entries len = %d, head = %d, want compacted single entry", len(rt.entries), rt.head)
	}
	if got := rt.Latest(); got != "fresh" {
		t.Fatalf("Latest() = %q, want fresh", got)
	}
}

func TestParseMemoryLimit(t *testing.T) {
	cases := []struct {
		value string
		want  int64
	}{
		{"300MiB", 300 << 20},
		{"300MIB", 300 << 20},
		{"512MB", 512 << 20},
		{"1GiB", 1 << 30},
		{"1GB", 1 << 30},
		{"1048576", 1048576},
		{"", 0},
		{"0", 0},
	}
	for _, tc := range cases {
		got, err := parseMemoryLimit(tc.value)
		if err != nil {
			t.Fatalf("parseMemoryLimit(%q) error: %v", tc.value, err)
		}
		if got != tc.want {
			t.Fatalf("parseMemoryLimit(%q) = %d, want %d", tc.value, got, tc.want)
		}
	}
}

func TestParseMemoryLimitRejectsGarbage(t *testing.T) {
	for _, value := range []string{"abc", "300MBB", "-1", "12.5MB", "9223372036854775807KiB"} {
		if _, err := parseMemoryLimit(value); err == nil {
			t.Fatalf("parseMemoryLimit(%q) accepted invalid input", value)
		}
	}
}
