package warp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	nodeStoreVersion = 1
	defaultNodeZone  = "America/New_York"
	dayLayout        = "2006-01-02"
	failReasonLimit  = 120
	buildFailLimit   = 3
)

// nodeRecord 是节点库中的一条出口凭据.
type nodeRecord struct {
	Prefix      string       `json:"prefix"`
	Egress      string       `json:"egress"`
	Stack       Stack        `json:"stack"`
	Source      string       `json:"source,omitempty"`
	Reg         registration `json:"registration"`
	Success     int          `json:"success"`
	Fail        int          `json:"fail"`
	BuildFail   int          `json:"build_fail"`
	LastFailDay string       `json:"last_fail_day,omitempty"`
	LastFailWhy string       `json:"last_fail_reason,omitempty"`
	LastOKDay   string       `json:"last_ok_day,omitempty"`
	LastUsedDay string       `json:"last_used_day,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	Disabled    bool         `json:"disabled,omitempty"`
}

// NodeStats 是节点库的汇总量.
type NodeStats struct {
	Enabled     bool   `json:"enabled"`
	Zone        string `json:"zone"`
	Day         string `json:"day"`
	Total       int    `json:"total"`
	Good        int    `json:"good"`
	Available   int    `json:"available"`
	UsedToday   int    `json:"used_today"`
	FailedToday int    `json:"failed_today"`
	Disabled    int    `json:"disabled"`
}

// NodeView 是 GET /nodes 的只读视图, 不含注册凭据.
type NodeView struct {
	Prefix      string    `json:"prefix"`
	Egress      string    `json:"egress"`
	Stack       string    `json:"stack"`
	Success     int       `json:"success"`
	Fail        int       `json:"fail"`
	BuildFail   int       `json:"build_fail"`
	LastUsedDay string    `json:"last_used_day,omitempty"`
	LastFailDay string    `json:"last_fail_day,omitempty"`
	LastOKDay   string    `json:"last_ok_day,omitempty"`
	LastFailWhy string    `json:"last_fail_reason,omitempty"`
	Disabled    bool      `json:"disabled"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type nodeStore struct {
	path  string
	zone  string
	loc   *time.Location
	mu    sync.Mutex
	nodes map[string]*nodeRecord
	dirty bool
}

type nodeFile struct {
	Version int          `json:"version"`
	Nodes   []nodeRecord `json:"nodes"`
}

// openNodeStore 打开节点库; path 为空表示关闭.
func openNodeStore(path, zone string) (*nodeStore, error) {
	if path == "" {
		return nil, nil
	}
	zone = strings.TrimSpace(zone)
	if zone == "" {
		zone = defaultNodeZone
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return nil, fmt.Errorf("load WARP node store zone %q: %w", zone, err)
	}
	store := &nodeStore{
		path:  path,
		zone:  zone,
		loc:   loc,
		nodes: make(map[string]*nodeRecord),
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return store, nil
		}
		return nil, fmt.Errorf("read WARP node store %s: %w", path, err)
	}
	var file nodeFile
	if err := json.Unmarshal(payload, &file); err != nil {
		return nil, fmt.Errorf("decode WARP node store %s: %w", path, err)
	}
	for index := range file.Nodes {
		record := file.Nodes[index]
		if record.Prefix == "" {
			continue
		}
		copied := record
		store.nodes[record.Prefix] = &copied
	}
	return store, nil
}

// day 返回该时刻在配置时区下的日期.
func (s *nodeStore) day(t time.Time) string {
	loc := s.loc
	if loc == nil {
		loc = time.UTC
	}
	return t.In(loc).Format(dayLayout)
}

// has 报告该段是否已有记录.
func (s *nodeStore) has(prefix string) bool {
	if prefix == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.nodes[prefix]
	return ok
}

// put 按 Prefix 落库, 合并时保留历史统计.
func (s *nodeStore) put(rec nodeRecord, now time.Time) {
	if rec.Prefix == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nodes == nil {
		s.nodes = make(map[string]*nodeRecord)
	}
	rec.Reg = cloneRegistration(rec.Reg)
	if existing, ok := s.nodes[rec.Prefix]; ok {
		merged := *existing
		merged.Egress = rec.Egress
		merged.Stack = rec.Stack
		merged.Source = rec.Source
		merged.Reg = rec.Reg
		merged.UpdatedAt = now
		s.nodes[rec.Prefix] = &merged
		s.dirty = true
		return
	}
	rec.CreatedAt = now
	rec.UpdatedAt = now
	copied := rec
	s.nodes[rec.Prefix] = &copied
	s.dirty = true
}

// claim 标记该段今天已激活.
func (s *nodeStore) claim(prefix string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.nodes[prefix]
	if !ok {
		return
	}
	record.LastUsedDay = s.day(now)
	record.UpdatedAt = now
	s.dirty = true
}

// success 按完整出口 IP 记账, 命中返回 true.
func (s *nodeStore) success(egress string, now time.Time) bool {
	if egress == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.nodes {
		if record.Egress != egress {
			continue
		}
		record.Success++
		// 连续重建失败计数在出口可用后归零.
		record.BuildFail = 0
		record.LastOKDay = s.day(now)
		record.UpdatedAt = now
		s.dirty = true
		return true
	}
	return false
}

// fail 记录一次出口失败, 只影响当天.
func (s *nodeStore) fail(prefix, reason string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.nodes[prefix]
	if !ok {
		return
	}
	record.Fail++
	record.LastFailDay = s.day(now)
	record.LastFailWhy = truncateReason(reason)
	record.UpdatedAt = now
	s.dirty = true
}

// buildFail 记录重建失败; 连续 3 次失败置 Disabled.
func (s *nodeStore) buildFail(prefix string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.nodes[prefix]
	if !ok {
		return
	}
	record.BuildFail++
	if record.BuildFail >= buildFailLimit {
		record.Disabled = true
	}
	record.UpdatedAt = now
	s.dirty = true
}

// drift 把记录迁到重建后的新段.
func (s *nodeStore) drift(oldPrefix, egress, newPrefix string, now time.Time) {
	if oldPrefix == "" || newPrefix == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if oldPrefix == newPrefix {
		if record, ok := s.nodes[oldPrefix]; ok {
			record.Egress = egress
			record.UpdatedAt = now
			s.dirty = true
		}
		return
	}
	record, ok := s.nodes[oldPrefix]
	if !ok {
		return
	}
	delete(s.nodes, oldPrefix)
	s.dirty = true
	if _, exists := s.nodes[newPrefix]; exists {
		return
	}
	record.Prefix = newPrefix
	record.Egress = egress
	record.UpdatedAt = now
	s.nodes[newPrefix] = record
}

// pick 选出今天还可激活的节点.
func (s *nodeStore) pick(now time.Time, skip map[string]bool) (nodeRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	today := s.day(now)
	eligible := make([]*nodeRecord, 0, len(s.nodes))
	for _, record := range s.nodes {
		if record.Disabled || record.LastUsedDay == today || record.LastFailDay == today {
			continue
		}
		if skip[record.Prefix] {
			continue
		}
		eligible = append(eligible, record)
	}
	chosen := make([]*nodeRecord, 0, len(eligible))
	for _, record := range eligible {
		if record.Success > 0 {
			chosen = append(chosen, record)
		}
	}
	if len(chosen) == 0 {
		chosen = eligible
	}
	if len(chosen) == 0 {
		return nodeRecord{}, false
	}
	sort.Slice(chosen, func(i, j int) bool {
		if chosen[i].Success != chosen[j].Success {
			return chosen[i].Success > chosen[j].Success
		}
		if chosen[i].LastUsedDay != chosen[j].LastUsedDay {
			return chosen[i].LastUsedDay < chosen[j].LastUsedDay
		}
		return chosen[i].Prefix < chosen[j].Prefix
	})
	return cloneRecord(chosen[0]), true
}

// stats 返回汇总量.
func (s *nodeStore) stats(now time.Time) NodeStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	today := s.day(now)
	stats := NodeStats{
		Enabled: true,
		Zone:    s.zone,
		Day:     today,
		Total:   len(s.nodes),
	}
	for _, record := range s.nodes {
		if record.Success > 0 && !record.Disabled {
			stats.Good++
		}
		if record.Disabled {
			stats.Disabled++
		}
		if record.LastUsedDay == today {
			stats.UsedToday++
		}
		if record.LastFailDay == today {
			stats.FailedToday++
		}
		if !record.Disabled && record.LastUsedDay != today && record.LastFailDay != today {
			stats.Available++
		}
	}
	return stats
}

// views 返回脱敏列表, limit<=0 表示不限.
func (s *nodeStore) views(limit int) []NodeView {
	s.mu.Lock()
	views := make([]NodeView, 0, len(s.nodes))
	for _, record := range s.nodes {
		views = append(views, NodeView{
			Prefix:      record.Prefix,
			Egress:      record.Egress,
			Stack:       string(record.Stack),
			Success:     record.Success,
			Fail:        record.Fail,
			BuildFail:   record.BuildFail,
			LastUsedDay: record.LastUsedDay,
			LastFailDay: record.LastFailDay,
			LastOKDay:   record.LastOKDay,
			LastFailWhy: record.LastFailWhy,
			Disabled:    record.Disabled,
			UpdatedAt:   record.UpdatedAt,
		})
	}
	s.mu.Unlock()
	sort.Slice(views, func(i, j int) bool {
		if views[i].Success != views[j].Success {
			return views[i].Success > views[j].Success
		}
		return views[i].Prefix < views[j].Prefix
	})
	if limit > 0 && len(views) > limit {
		views = views[:limit]
	}
	return views
}

// flush 把脏数据原子落盘(tmp+rename).
func (s *nodeStore) flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	nodes := make([]nodeRecord, 0, len(s.nodes))
	for _, record := range s.nodes {
		nodes = append(nodes, *record)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Prefix < nodes[j].Prefix })
	payload, err := json.MarshalIndent(nodeFile{Version: nodeStoreVersion, Nodes: nodes}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode WARP node store: %w", err)
	}
	payload = append(payload, '\n')
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create WARP node store directory %s: %w", dir, err)
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return fmt.Errorf("write WARP node store %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace WARP node store %s: %w", s.path, err)
	}
	s.dirty = false
	return nil
}

// Close 落盘并关闭.
func (s *nodeStore) Close() error {
	if s == nil {
		return nil
	}
	return s.flush()
}

// cloneRecord 深拷贝记录.
func cloneRecord(record *nodeRecord) nodeRecord {
	copied := *record
	copied.Reg = cloneRegistration(record.Reg)
	return copied
}

func cloneRegistration(reg registration) registration {
	if len(reg.Endpoints) != 0 {
		reg.Endpoints = append([]string(nil), reg.Endpoints...)
	}
	return reg
}

// truncateReason 按字节截断, 保留完整字符.
func truncateReason(reason string) string {
	if len(reason) <= failReasonLimit {
		return reason
	}
	cut := failReasonLimit
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut]
}
