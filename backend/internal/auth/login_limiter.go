package auth

import (
	"sync"
	"time"
)

type loginAttempt struct {
	count       int
	windowStart time.Time
}

// LoginLimiter is a bounded, in-process fixed-window limiter. The platform is
// intentionally a single control-plane binary, so no distributed dependency is
// required for enforcing login throttling.
type LoginLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
	limit    int
	window   time.Duration
	maxKeys  int
}

func NewLoginLimiter(limit int, window time.Duration, maxKeys ...int) *LoginLimiter {
	capacity := 4096
	if len(maxKeys) > 0 && maxKeys[0] > 0 {
		capacity = maxKeys[0]
	}
	return &LoginLimiter{attempts: map[string]loginAttempt{}, limit: limit, window: window, maxKeys: capacity}
}

func (l *LoginLimiter) Blocked(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanup(now)
	attempt, exists := l.attempts[key]
	if !exists || attempt.count < l.limit {
		return false, 0
	}
	retry := l.window - now.Sub(attempt.windowStart)
	if retry < time.Second {
		retry = time.Second
	}
	return true, retry
}

func (l *LoginLimiter) Failure(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	attempt, exists := l.attempts[key]
	if !exists || now.Sub(attempt.windowStart) >= l.window {
		if !exists && len(l.attempts) >= l.maxKeys {
			l.cleanup(now)
			if len(l.attempts) >= l.maxKeys {
				l.evictOldest()
			}
		}
		l.attempts[key] = loginAttempt{count: 1, windowStart: now}
		return
	}
	attempt.count++
	l.attempts[key] = attempt
}

func (l *LoginLimiter) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, attempt := range l.attempts {
		if oldestKey == "" || attempt.windowStart.Before(oldest) {
			oldestKey, oldest = key, attempt.windowStart
		}
	}
	if oldestKey != "" {
		delete(l.attempts, oldestKey)
	}
}

func (l *LoginLimiter) Success(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}

func (l *LoginLimiter) cleanup(now time.Time) {
	for key, attempt := range l.attempts {
		if now.Sub(attempt.windowStart) >= l.window {
			delete(l.attempts, key)
		}
	}
}
