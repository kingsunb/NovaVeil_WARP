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
		{addr: "fresh", at: now.Add(-time.Second)},
		{addr: "expired", at: now.Add(-time.Minute - time.Second)},
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
