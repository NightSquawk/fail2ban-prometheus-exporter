package socket

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newSilentServer starts a unix listener that accepts connections and then
// never answers, standing in for a wedged fail2ban server.
func newSilentServer(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "f2b.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				<-done
				_ = conn.Close()
			}()
		}
	}()
	return path
}

// TestCommandTimesOutOnSilentServer is the regression test for scrapes hanging
// forever: without a deadline this blocks in read() until the process dies, and
// because Collect holds a mutex for its whole duration every later scrape
// queues behind it.
func TestCommandTimesOutOnSilentServer(t *testing.T) {
	s, err := ConnectToSocketTimeout(newSilentServer(t), 200*time.Millisecond)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer s.Close()

	start := time.Now()
	_, err = s.Ping()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Ping to fail against a server that never responds")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("expected a deadline error, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Ping took %v, expected it to give up near the 200ms timeout", elapsed)
	}
}

// TestDeadlineIsPerCommand checks the deadline is refreshed for each command
// rather than being a budget for the socket's whole lifetime.
func TestDeadlineIsPerCommand(t *testing.T) {
	s, err := ConnectToSocketTimeout(newSilentServer(t), 100*time.Millisecond)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer s.Close()

	for i := 0; i < 3; i++ {
		start := time.Now()
		if _, err := s.Ping(); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("call %d: expected a deadline error, got: %v", i, err)
		}
		if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
			t.Errorf("call %d returned after %v, suggesting a stale deadline rather than a fresh one", i, elapsed)
		}
	}
}

func TestZeroTimeoutSetsNoDeadline(t *testing.T) {
	s, err := ConnectToSocketTimeout(newSilentServer(t), 0)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer s.Close()

	// With no deadline the call blocks, so only assert that it is still blocked
	// after a window that the 200ms-timeout case above comfortably exceeds.
	done := make(chan struct{})
	go func() {
		_, _ = s.Ping()
		close(done)
	}()
	select {
	case <-done:
		t.Error("Ping returned even though no deadline was configured")
	case <-time.After(500 * time.Millisecond):
	}
}

func TestConnectToSocketTimeoutFailsOnMissingSocket(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.sock")
	if _, err := ConnectToSocketTimeout(missing, time.Second); err == nil {
		t.Error("expected an error connecting to a socket that does not exist")
	}
}
