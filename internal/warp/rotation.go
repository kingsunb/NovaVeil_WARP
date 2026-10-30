package warp

import (
	"errors"
	"time"
)

const (
	rotationGap          = 4 * time.Second
	rotationWindow       = time.Hour
	maxRotationsPerKey   = 60
	maxFullRekeysPerHour = 60
	rotationBackoffBase  = 15 * time.Second
	rotationBackoffCap   = 300 * time.Second
)

var (
	errEgressPrefixUnchanged = errors.New("WARP egress prefix unchanged")
	// errCannotPlaceRotated 表示候选出口无法入池, 需要换段重建.
	errCannotPlaceRotated = errors.New("cannot place rotated WARP exit")
	// errCannotPlaceRekeyed 表示换段重建后的出口仍无法入池.
	errCannotPlaceRekeyed = errors.New("cannot place re-keyed WARP exit")
)

type rotationFailure struct {
	count int
	until time.Time
}

// rotationBackoff 返回第 n 次连续失败后的退避.
func rotationBackoff(failures int) time.Duration {
	delay := rotationBackoffBase
	for index := 0; index < failures; index++ {
		if delay >= rotationBackoffCap {
			return rotationBackoffCap
		}
		delay *= 2
	}
	if delay > rotationBackoffCap {
		return rotationBackoffCap
	}
	return delay
}

func pruneRotationTimes(times []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	kept := times[:0]
	for _, at := range times {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	return kept
}

// rotate 串行执行一次出口轮换.
func (p *Pool) rotate(old *exit, reason string) {
	p.rotateMu.Lock()
	defer p.rotateMu.Unlock()
	if old == nil {
		return
	}
	defer p.startRefill()
	if p.keyRotations == nil {
		p.keyRotations = make(map[string][]time.Time)
	}
	if p.rotationFailures == nil {
		p.rotationFailures = make(map[string]rotationFailure)
	}
	if p.ctx.Err() != nil {
		return
	}
	if wait := rotationGap - time.Since(p.lastRotateStart); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
			return
		case <-timer.C:
		}
	}

	now := time.Now()
	key := old.egressKey()
	if key == "" {
		key = old.id
	}
	p.pruneRotationStateLocked(now)
	if failure, ok := p.rotationFailures[key]; ok && failure.until.After(now) {
		p.warnf("WARP rotation for %s backs off until %s, keeping %s retired", key, failure.until.Format(time.RFC3339), old.egress)
		return
	}
	if len(p.keyRotations[key]) >= maxRotationsPerKey {
		p.warnf("WARP rotation budget for %s exhausted, keeping %s retired", key, old.egress)
		return
	}
	p.lastRotateStart = now
	p.keyRotations[key] = append(p.keyRotations[key], now)

	candidate, err := p.softRestart(old)
	if err == nil && candidate != nil && !sameEgressPrefix(candidate.egress, old.egress) {
		if p.placeRotated(old, candidate, false) {
			p.clearRotationFailureLocked(key)
			p.infof("OpenCode WARP egress %s rotated to %s (%s)", old.id, candidate.egress, reason)
			return
		}
		candidate.close()
		err = errCannotPlaceRotated
	} else {
		if candidate != nil {
			candidate.close()
		}
		if err == nil {
			err = errEgressPrefixUnchanged
		}
	}
	// 放置失败同样走换段重建: soft restart 复用旧注册, 落点常常还在刚被
	// 惩罚的段上, 只有换段才能真正换掉配额作用域.
	if errors.Is(err, errEgressPrefixUnchanged) || errors.Is(err, errCannotPlaceRotated) {
		if !p.takeFullRekeyLocked(now) {
			p.warnf("WARP full re-key budget exhausted, keeping %s retired", old.egress)
			return
		}
		candidate, err = p.createExit(p.ctx)
		if err == nil && candidate != nil && !sameEgressPrefix(candidate.egress, old.egress) {
			if p.placeRotated(old, candidate, true) {
				p.clearRotationFailureLocked(key)
				p.infof("OpenCode WARP egress %s re-keyed to %s (%s)", old.id, candidate.egress, reason)
				return
			}
			p.releaseReservation(candidate)
			candidate.close()
			err = errCannotPlaceRekeyed
		} else {
			if candidate != nil {
				p.releaseReservation(candidate)
				candidate.close()
			}
			if err == nil {
				err = errEgressPrefixUnchanged
			}
		}
	}

	delay := p.recordRotationFailureLocked(key, time.Now())
	p.warnf("WARP rotation for %s failed (%v), keeping %s retired, next attempt after %s", key, err, old.egress, delay)
}

func (p *Pool) softRestart(old *exit) (*exit, error) {
	source := old.source
	if p.sourcePrefix.IsValid() && old.stack == StackIPv6 {
		var err error
		source, err = randomSource(p.sourcePrefix)
		if err != nil {
			return nil, err
		}
	}
	return newExitWithStack(p.ctx, old.reg, old.stack, source)
}

func (p *Pool) placeRotated(old, candidate *exit, reserved bool) bool {
	if reserved {
		if !p.claimReservedCandidate(candidate) {
			return false
		}
	} else if !p.claimCandidate(candidate) {
		return false
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.releaseReservation(candidate)
		return false
	}
	if index := p.activeIndexLocked(old); index >= 0 {
		p.active = append(p.active[:index], p.active[index+1:]...)
		if p.next >= len(p.active) {
			p.next = 0
		}
	}
	var evicted *exit
	if len(p.active) >= p.size {
		evicted = p.dropIdleLocked(old)
	}
	if len(p.active) >= p.size {
		p.mu.Unlock()
		if evicted != nil {
			p.releaseReservation(evicted)
			evicted.retire()
		}
		p.releaseReservation(candidate)
		return false
	}
	p.active = append(p.active, candidate)
	releases := p.bindSlotsLocked()
	p.notifyLocked()
	p.mu.Unlock()

	if evicted != nil {
		p.releaseReservation(evicted)
		evicted.retire()
	}
	p.releaseExits(releases)
	// 旧出口退役后释放它的段占用, 否则该配额段被永久标记为已用.
	if oldKey := old.egressKey(); oldKey != "" && oldKey != candidate.egressKey() {
		p.releaseReservation(old)
	}
	old.retire()
	p.startRefill()
	return true
}

func (p *Pool) claimCandidate(candidate *exit) bool {
	if candidate == nil {
		return false
	}
	key := candidate.egressKey()
	if key == "" {
		return false
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for subnet, until := range p.cooling {
		if !until.After(now) {
			delete(p.cooling, subnet)
		}
	}
	if p.reserved[key] || p.cooling[key].After(now) {
		return false
	}
	p.reserved[key] = true
	return true
}

// claimReservedCandidate 接受已预留的候选出口.
func (p *Pool) claimReservedCandidate(candidate *exit) bool {
	if candidate == nil {
		return false
	}
	key := candidate.egressKey()
	if key == "" {
		return false
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for subnet, until := range p.cooling {
		if !until.After(now) {
			delete(p.cooling, subnet)
		}
	}
	if !p.reserved[key] {
		return false
	}
	if p.cooling[key].After(now) {
		delete(p.reserved, key)
		return false
	}
	return true
}

func (p *Pool) dropIdleLocked(except *exit) *exit {
	for index, candidate := range p.active {
		// 槽位会在 bindSlotsLocked 里重绑, 因此绑着槽位的空闲出口也能挤掉.
		if candidate == except || !candidate.idle() {
			continue
		}
		p.active = append(p.active[:index], p.active[index+1:]...)
		if p.next >= len(p.active) {
			p.next = 0
		}
		return candidate
	}
	return nil
}

func (p *Pool) pruneRotationStateLocked(now time.Time) {
	for key, times := range p.keyRotations {
		times = pruneRotationTimes(times, now, rotationWindow)
		if len(times) == 0 {
			delete(p.keyRotations, key)
			continue
		}
		p.keyRotations[key] = times
	}
	p.fullRekeys = pruneRotationTimes(p.fullRekeys, now, rotationWindow)
}

func (p *Pool) takeFullRekeyLocked(now time.Time) bool {
	p.fullRekeys = pruneRotationTimes(p.fullRekeys, now, rotationWindow)
	if len(p.fullRekeys) >= maxFullRekeysPerHour {
		return false
	}
	p.fullRekeys = append(p.fullRekeys, now)
	return true
}

func (p *Pool) recordRotationFailureLocked(key string, now time.Time) time.Duration {
	failure := p.rotationFailures[key]
	delay := rotationBackoff(failure.count)
	failure.count++
	failure.until = now.Add(delay)
	p.rotationFailures[key] = failure
	return delay
}

func (p *Pool) clearRotationFailureLocked(key string) {
	delete(p.rotationFailures, key)
}

func (p *Pool) warnf(format string, args ...interface{}) {
	if p.logger != nil {
		p.logger.Warnf(format, args...)
	}
}

func (p *Pool) infof(format string, args ...interface{}) {
	if p.logger != nil {
		p.logger.Infof(format, args...)
	}
}
