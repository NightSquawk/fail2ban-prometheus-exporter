package f2b

import (
	"path/filepath"
	"testing"
	"time"
)

// TestIsHealthyDoesNotMutateErrorCounters is the regression test for the M3
// security fix: /health (server/handler.go) is unauthenticated, so a failed
// probe must never advance socketConnectionErrorCount /
// socketRequestErrorCount. Those two counters feed
// f2b_errors_total{type="socket_conn"|"socket_req"} on /metrics; letting an
// anonymous caller move them by hammering /health while fail2ban is down
// would poison a metric operators alert on.
func TestIsHealthyDoesNotMutateErrorCounters(t *testing.T) {
	t.Run("dial failure", func(t *testing.T) {
		c := &Collector{
			socketPath:    filepath.Join(t.TempDir(), "does-not-exist.sock"),
			socketTimeout: 200 * time.Millisecond,
		}
		for i := 0; i < 3; i++ {
			if c.IsHealthy() {
				t.Fatalf("IsHealthy() = true against a socket that does not exist")
			}
		}
		if c.socketConnectionErrorCount != 0 {
			t.Errorf("socketConnectionErrorCount = %d, want 0 after %d failed dials via IsHealthy", c.socketConnectionErrorCount, 3)
		}
	})

	t.Run("ping failure", func(t *testing.T) {
		srv := newFakeF2BServer(t, fakeF2BFixture{})
		srv.SetMalformed(true)

		c := &Collector{
			socketPath:    srv.SocketPath(),
			socketTimeout: time.Second,
		}
		for i := 0; i < 3; i++ {
			if c.IsHealthy() {
				t.Fatalf("IsHealthy() = true against a malformed ping response")
			}
		}
		if c.socketRequestErrorCount != 0 {
			t.Errorf("socketRequestErrorCount = %d, want 0 after %d failed pings via IsHealthy", c.socketRequestErrorCount, 3)
		}
	})
}

// TestIsHealthyPingSuccess proves the happy path still returns true against a
// live, responsive fail2ban socket.
func TestIsHealthyPingSuccess(t *testing.T) {
	srv := newFakeF2BServer(t, fakeF2BFixture{Version: "1.0.2"})

	c := &Collector{
		socketPath:    srv.SocketPath(),
		socketTimeout: time.Second,
	}
	if !c.IsHealthy() {
		t.Fatalf("IsHealthy() = false against a live, responsive fail2ban socket")
	}
}

// TestIsHealthyNeverExits proves a failed probe cannot trigger os.Exit(1)
// even with --collector.f2b.exit-on-socket-connection-error set: only
// Collect()'s top-level dial (snapshotLocked, gated by
// SnapshotOptions.HonorExitOnSocketConnError, which IsHealthy never sets)
// may do that. If IsHealthy ever gained that capability, this test's process
// would exit before reaching the assertion below instead of failing it
// cleanly.
func TestIsHealthyNeverExits(t *testing.T) {
	c := &Collector{
		socketPath:            filepath.Join(t.TempDir(), "does-not-exist.sock"),
		socketTimeout:         200 * time.Millisecond,
		exitOnSocketConnError: true,
	}
	if c.IsHealthy() {
		t.Fatalf("IsHealthy() = true against a socket that does not exist")
	}
}

// TestIdentity pins Identity() to the package's exporterName const and the
// version threaded through at construction, so /health (server/handler.go)
// never needs its own copy of either.
func TestIdentity(t *testing.T) {
	c := &Collector{exporterVersion: "1.2.3-test"}
	name, version := c.Identity()
	if name != exporterName {
		t.Errorf("name = %q, want %q", name, exporterName)
	}
	if version != "1.2.3-test" {
		t.Errorf("version = %q, want %q", version, "1.2.3-test")
	}
}
