package auth

import (
	"testing"
	"time"
)

func TestLoginLimiterBlocksAndResets(t *testing.T) {
	limiter := NewLoginLimiter(2, time.Minute)
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	limiter.Failure("client", now)
	if blocked, _ := limiter.Blocked("client", now); blocked {
		t.Fatal("blocked too early")
	}
	limiter.Failure("client", now)
	if blocked, retry := limiter.Blocked("client", now); !blocked || retry != time.Minute {
		t.Fatalf("blocked=%v retry=%v", blocked, retry)
	}
	limiter.Success("client")
	if blocked, _ := limiter.Blocked("client", now); blocked {
		t.Fatal("success did not reset limiter")
	}
	limiter.Failure("client", now)
	if blocked, _ := limiter.Blocked("client", now.Add(time.Minute)); blocked {
		t.Fatal("window did not expire")
	}
}
