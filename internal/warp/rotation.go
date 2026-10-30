package warp

import (
	"errors"
	"time"
)

const (
	rotationGap          = 4 * time.Second
	rotationWindow       = time.Hour
	maxRotationsPerKey   = 2
	maxFullRekeysPerHour = 60
	rotationBackoffBase  = 300 * time.Second
	rotationBackoffCap   = 3600 * time.Second
)

var errEgressPrefixUnchanged = errors.New("WARP egress prefix unchanged")

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
	if p.keyRotations == nil {
		p.keyRotations = make(map[string][]time.Time)
	}
	if p.rotationFailures == nil {
		p.rotationFailures = make(map[string]rotationFailure)
	}
	if p.ctx.Err() != nil {
		p.restoreExit(old)
		return
	}
	if wait := rotationGap - time.Since(p.lastRotateStart); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
			p.restoreExit(old)
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
		p.warnf("WARP rotation for %s backs off until %s, restoring %s", key, failure.until.Format(time.RFC3339), old.egress)
		p.restoreExit(old)
		return
	}
	if len(p.keyRotations[key]) >= maxRotationsPerKey {
		p.warnf("WARP rotation budget for %s exhausted, restoring %s", key, old.egress)
		p.restoreExit(old)
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
		err = errors.New("cannot place rotated WARP exit")
	} else {
		if candidate != nil {
			candidate.close()
		}
		if err == nil {
			err = errEgressPrefixUnchanged
		}
	}
	if errors.Is(err, errEgressPrefixUnchanged) {
		if !p.takeFullRekeyLocked(now) {
			p.warnf("WARP full re-key budget exhausted, restoring %s", old.egress)
			p.restoreExit(old)
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
			err = errors.New("cannot place re-keyed WARP exit")
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
	p.warnf("WARP rotation for %s failed (%v), restoring %s, next attempt after %s", key, err, old.egress, delay)
	p.restoreExit(old)
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
		if candidate == except || p.slotBoundLocked(candidate) || !candidate.idle() {
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

func (p *Pool) restoreExit(old *exit) {
	if old == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		old.retire()
		return
	}
	if p.activeIndexLocked(old) >= 0 {
		old.clearPenalty()
		if key := old.egressKey(); key != "" {
			p.reserved[key] = true
			delete(p.cooling, key)
		}
		releases := p.bindSlotsLocked()
		p.notifyLocked()
		p.mu.Unlock()
		p.releaseExits(releases)
		p.startRefill()
		return
	}
	var evicted *exit
	if len(p.active) >= p.size {
		evicted = p.dropIdleLocked(old)
	}
	if len(p.active) >= p.size {
		if key := old.egressKey(); key != "" {
			delete(p.cooling, key)
		}
		p.mu.Unlock()
		old.retire()
		return
	}
	old.clearPenalty()
	if key := old.egressKey(); key != "" {
		p.reserved[key] = true
		delete(p.cooling, key)
	}
	p.active = append(p.active, old)
	releases := p.bindSlotsLocked()
	p.notifyLocked()
	p.mu.Unlock()

	if evicted != nil {
		p.releaseReservation(evicted)
		evicted.retire()
	}
	p.releaseExits(releases)
	p.startRefill()
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
