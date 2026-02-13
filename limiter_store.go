package gitealimit

import "time"

func (m *GiteaIPLimit) allowAnonymous(ip string, now time.Time) (bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	window := time.Duration(m.Window)
	entry, ok := m.anonymousIPs[ip]
	if !ok || now.Sub(entry.windowStart) >= window {
		m.anonymousIPs[ip] = &anonWindow{
			windowStart: now,
			count:       1,
		}
		return true, 0
	}

	if entry.count >= m.Limit {
		retryAfter := window - now.Sub(entry.windowStart)
		if retryAfter < 0 {
			retryAfter = 0
		}
		return false, retryAfter
	}

	entry.count++
	return true, 0
}

func (m *GiteaIPLimit) cleanupLocked(now time.Time) {
	if now.Sub(m.lastCleanup) < time.Minute {
		return
	}
	m.lastCleanup = now

	for ip, expireAt := range m.trustedIPs {
		if !now.Before(expireAt) {
			delete(m.trustedIPs, ip)
		}
	}

	window := time.Duration(m.Window)
	for ip, entry := range m.anonymousIPs {
		if now.Sub(entry.windowStart) >= window {
			delete(m.anonymousIPs, ip)
		}
	}

	for ip, t := range m.nextVerifyAt {
		if !now.Before(t) {
			delete(m.nextVerifyAt, ip)
		}
	}
}
