package http

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestRaceDials_PrefersReachableOverStalled reproduces the bug behind the slow
// loopback requests: a sequential dialer that probes a dead address first
// (e.g. ::1 when nothing listens there, whose SYN is silently dropped on WSL2)
// blocks the whole request until that probe times out. raceDials must return
// the reachable connection immediately instead of serializing behind the dead
// one. A sequential implementation hangs here until the dead dial unblocks.
func TestRaceDials_PrefersReachableOverStalled(t *testing.T) {
	live, peer := net.Pipe()
	defer peer.Close()

	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		if addr == "dead:0" {
			<-ctx.Done() // simulate a dropped SYN: blocks until cancelled
			return nil, ctx.Err()
		}
		return live, nil
	}

	start := time.Now()
	conn, err := raceDials(context.Background(), dial, "tcp", []string{"dead:0", "live:0"})
	if err != nil {
		t.Fatalf("raceDials: %v", err)
	}
	if conn != live {
		t.Fatal("raceDials returned the wrong connection")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("raceDials stalled %v behind the dead peer; want near-instant", d)
	}
	conn.Close()
}

// TestSleepCtx_AbortsOnCancel verifies a backoff returns immediately with the
// context error when the scan is cancelled, instead of blocking the full timer.
func TestSleepCtx_AbortsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if err := sleepCtx(ctx, 10*time.Second); err == nil {
		t.Fatal("sleepCtx: want error on cancelled context, got nil")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("sleepCtx blocked %v after cancel; want near-instant", d)
	}
}

// TestSleepCtx_CompletesNormally verifies it waits out a short delay and
// returns nil when not cancelled.
func TestSleepCtx_CompletesNormally(t *testing.T) {
	if err := sleepCtx(context.Background(), 10*time.Millisecond); err != nil {
		t.Fatalf("sleepCtx: unexpected error: %v", err)
	}
}

// TestRaceDials_AllFail surfaces an error when no target is reachable.
func TestRaceDials_AllFail(t *testing.T) {
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("refused %s", addr)
	}
	conn, err := raceDials(context.Background(), dial, "tcp", []string{"a:0", "b:0"})
	if err == nil {
		conn.Close()
		t.Fatal("raceDials: want error when all targets fail, got nil")
	}
}

func TestRaceDials_EmptyAddrs(t *testing.T) {
	dial := func(_ context.Context, _, _ string) (net.Conn, error) {
		t.Fatal("dial should not be called with no addresses")
		return nil, nil
	}
	conn, err := raceDials(context.Background(), dial, "tcp", nil)
	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("raceDials: want error for empty addrs, got (conn, nil)")
	}
}
