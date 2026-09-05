package f2b

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	ogorek "github.com/kisielk/og-rek"
	"github.com/nlpodyssey/gopickle/pickle"
	"github.com/nlpodyssey/gopickle/types"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/socket"
)

// commandTerminator mirrors the unexported constant in package socket; the
// wire protocol is symmetric (command/response both end with this literal),
// so the fake server needs its own copy to frame reads and writes.
const commandTerminator = "<F2B_END_COMMAND>"

const fakeSocketReadBufferSize = 1024

// fakeJailFixture describes one jail's worth of canned socket responses.
type fakeJailFixture struct {
	Name          string
	FailedCurrent int
	FailedTotal   int
	BannedCurrent int
	BannedTotal   int
	BannedIPs     string // comma-separated, matching socket.GetBannedIPs parsing
	BanTime       int
	FindTime      int
	MaxRetry      int
}

// fakeF2BFixture is the plain Go struct a test fills in to drive the fake
// fail2ban server.
type fakeF2BFixture struct {
	Version string
	Jails   []fakeJailFixture
}

func (f fakeF2BFixture) jail(name string) (fakeJailFixture, bool) {
	for _, j := range f.Jails {
		if j.Name == name {
			return j, true
		}
	}
	return fakeJailFixture{}, false
}

// fakeF2BServer serves the fail2ban unix-socket pickle protocol against a
// fixture, for exercising the real socket.* client without a live fail2ban.
type fakeF2BServer struct {
	listener net.Listener
	wg       sync.WaitGroup

	mu        sync.Mutex
	fixture   fakeF2BFixture
	malformed bool
	conns     map[net.Conn]struct{}
}

// newFakeF2BServer starts a fake fail2ban socket server listening on a fresh
// unix socket and returns it. The listener accepts connections until Close
// is called; each connection is served in its own goroutine and may carry
// multiple sequential commands, matching the real fail2ban-client protocol.
func newFakeF2BServer(t testing.TB, fixture fakeF2BFixture) *fakeF2BServer {
	t.Helper()

	path := fakeSocketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on fake fail2ban socket %s: %v", path, err)
	}

	s := &fakeF2BServer{listener: ln, fixture: fixture, conns: make(map[net.Conn]struct{})}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

// fakeSocketPath returns a path for a unix socket, short enough to fit
// sun_path (~104 bytes on Linux/BSD). t.TempDir() nests deeply enough
// (especially under -run with long subtest names) that it can exceed this,
// so fall back to a short directory directly under os.TempDir().
func fakeSocketPath(t testing.TB) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "f2b.sock")
	if len(path) < 100 {
		return path
	}

	short, err := os.MkdirTemp(os.TempDir(), "f2bsock")
	if err != nil {
		t.Fatalf("create short socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	return filepath.Join(short, "f2b.sock")
}

func (s *fakeF2BServer) SocketPath() string {
	return s.listener.Addr().String()
}

// SetMalformed toggles whether every subsequent response is garbage that
// fails the client's type assertions, for exercising bad-format error paths.
func (s *fakeF2BServer) SetMalformed(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.malformed = v
}

// Close stops accepting connections and force-closes every connection still
// open. net.Listen("unix", ...) unlinks the socket file on Close, so
// subsequent dials to this path fail outright - this is how tests simulate
// fail2ban refusing connections entirely. Force-closing live connections
// (rather than waiting for clients to hang up) matters because a test that
// ends without every client having hung up - e.g. one asserting mid-gather
// behaviour, or a future call site that forgets its own Close - would
// otherwise leave a handleConn goroutine blocked on read forever, and
// wg.Wait below would never return.
func (s *fakeF2BServer) Close() {
	_ = s.listener.Close()

	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}

	s.wg.Wait()
}

func (s *fakeF2BServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

func (s *fakeF2BServer) handleConn(conn net.Conn) {
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()
	for {
		cmd, err := readCommand(conn)
		if err != nil {
			return
		}
		resp := s.buildResponse(cmd)
		if err := writeResponse(conn, resp); err != nil {
			return
		}
	}
}

func (s *fakeF2BServer) buildResponse(cmd []string) interface{} {
	s.mu.Lock()
	malformed := s.malformed
	fixture := s.fixture
	s.mu.Unlock()

	if malformed {
		// A bare string fails every *types.Tuple / *types.List assertion in
		// socket/fail2banSocket.go, so every getter hits its bad-format path.
		return "malformed-response"
	}

	if len(cmd) == 0 {
		return errorResponse("empty command")
	}

	switch cmd[0] {
	case "ping":
		return ogorek.Tuple{0, "pong"}
	case "status":
		if len(cmd) == 1 {
			return statusAllResponse(fixture)
		}
		return statusJailResponse(fixture, cmd[1])
	case "version":
		return ogorek.Tuple{0, fixture.Version}
	case "get":
		if len(cmd) != 3 {
			return errorResponse("malformed get command")
		}
		return getConfigResponse(fixture, cmd[1], cmd[2])
	default:
		return errorResponse("unknown command: " + strings.Join(cmd, " "))
	}
}

func statusAllResponse(f fakeF2BFixture) ogorek.Tuple {
	names := make([]string, len(f.Jails))
	for i, j := range f.Jails {
		names[i] = j.Name
	}
	list := []interface{}{
		ogorek.Tuple{"Number of jail", len(names)},
		ogorek.Tuple{"Jail list", strings.Join(names, ", ")},
	}
	return ogorek.Tuple{0, list}
}

func statusJailResponse(f fakeF2BFixture, jailName string) interface{} {
	jail, ok := f.jail(jailName)
	if !ok {
		return errorResponse("sorry but no '" + jailName + "' jail")
	}

	filterList := []interface{}{
		ogorek.Tuple{"Currently failed", jail.FailedCurrent},
		ogorek.Tuple{"Total failed", jail.FailedTotal},
	}
	actionsList := []interface{}{
		ogorek.Tuple{"Currently banned", jail.BannedCurrent},
		ogorek.Tuple{"Total banned", jail.BannedTotal},
		ogorek.Tuple{"Banned IP list", jail.BannedIPs},
	}
	top := []interface{}{
		ogorek.Tuple{"Filter", filterList},
		ogorek.Tuple{"Actions", actionsList},
	}
	return ogorek.Tuple{0, top}
}

func getConfigResponse(f fakeF2BFixture, jailName, what string) interface{} {
	jail, ok := f.jail(jailName)
	if !ok {
		return errorResponse("sorry but no '" + jailName + "' jail")
	}

	switch what {
	case "bantime":
		return ogorek.Tuple{0, jail.BanTime}
	case "findtime":
		return ogorek.Tuple{0, jail.FindTime}
	case "maxretry":
		return ogorek.Tuple{0, jail.MaxRetry}
	default:
		return errorResponse("unknown get target: " + what)
	}
}

func errorResponse(msg string) ogorek.Tuple {
	return ogorek.Tuple{1, msg}
}

// readCommand decodes one pickled []string command from conn, framed by the
// literal commandTerminator, mirroring how socket/protocol.go reads
// responses on the client side.
func readCommand(conn net.Conn) ([]string, error) {
	reader := bufio.NewReader(conn)

	var data []byte
	for {
		buf := make([]byte, fakeSocketReadBufferSize)
		n, err := reader.Read(buf)
		if err != nil {
			return nil, err
		}
		data = append(data, buf[:n]...)
		if bytes.Contains(data, []byte(commandTerminator)) {
			break
		}
	}

	unpickler := pickle.NewUnpickler(bytes.NewReader(data))
	v, err := unpickler.Load()
	if err != nil {
		return nil, fmt.Errorf("fake socket: decode command: %w", err)
	}

	list, ok := v.(*types.List)
	if !ok {
		return nil, fmt.Errorf("fake socket: command is %T, want list", v)
	}
	cmd := make([]string, list.Len())
	for i := 0; i < list.Len(); i++ {
		s, ok := list.Get(i).(string)
		if !ok {
			return nil, fmt.Errorf("fake socket: command element %d is %T, want string", i, list.Get(i))
		}
		cmd[i] = s
	}
	return cmd, nil
}

// writeResponse encodes resp into a buffer and writes it in a single Write
// call. The production client's read loop appends whole 1024-byte chunks
// regardless of how many bytes a given Read actually returned (see
// socket/protocol.go), which silently splices zero-padding into the stream
// if a response arrives fragmented across multiple reads. A real fail2ban
// server sends its response in one write, so writing here in one call keeps
// the fake server honest to that same assumption instead of tripping over
// an unrelated client-side quirk.
func writeResponse(conn net.Conn, resp interface{}) error {
	var buf bytes.Buffer
	enc := ogorek.NewEncoder(&buf)
	if err := enc.Encode(resp); err != nil {
		return err
	}
	buf.WriteString(commandTerminator)
	_, err := conn.Write(buf.Bytes())
	return err
}

// TestFakeSocketRoundTrip drives the real socket.ConnectToSocket client
// against the fake server and asserts every getter returns the fixture
// values. This is the proof that fakesocket_test.go actually speaks the
// protocol socket/ expects, independent of anything in collector.go.
func TestFakeSocketRoundTrip(t *testing.T) {
	fixture := fakeF2BFixture{
		Version: "1.0.2",
		Jails: []fakeJailFixture{
			{
				Name:          "sshd",
				FailedCurrent: 3,
				FailedTotal:   42,
				BannedCurrent: 2,
				BannedTotal:   7,
				BannedIPs:     "192.0.2.1,192.0.2.2",
				BanTime:       3600,
				FindTime:      600,
				MaxRetry:      5,
			},
			{
				Name:          "apache-auth",
				FailedCurrent: 0,
				FailedTotal:   10,
				BannedCurrent: 1,
				BannedTotal:   1,
				BannedIPs:     "198.51.100.9",
				BanTime:       7200,
				FindTime:      300,
				MaxRetry:      3,
			},
		},
	}

	srv := newFakeF2BServer(t, fixture)

	s, err := socket.ConnectToSocket(srv.SocketPath())
	if err != nil {
		t.Fatalf("ConnectToSocket: %v", err)
	}
	defer s.Close()

	if ok, err := s.Ping(); err != nil || !ok {
		t.Fatalf("Ping() = %v, %v; want true, nil", ok, err)
	}

	jails, err := s.GetJails()
	if err != nil {
		t.Fatalf("GetJails: %v", err)
	}
	if len(jails) != 2 || jails[0] != "sshd" || jails[1] != "apache-auth" {
		t.Fatalf("GetJails = %v, want [sshd apache-auth]", jails)
	}

	version, err := s.GetServerVersion()
	if err != nil {
		t.Fatalf("GetServerVersion: %v", err)
	}
	if version != fixture.Version {
		t.Errorf("GetServerVersion = %q, want %q", version, fixture.Version)
	}

	for _, want := range fixture.Jails {
		stats, err := s.GetJailStats(want.Name)
		if err != nil {
			t.Fatalf("GetJailStats(%s): %v", want.Name, err)
		}
		if stats.FailedCurrent != want.FailedCurrent || stats.FailedTotal != want.FailedTotal ||
			stats.BannedCurrent != want.BannedCurrent || stats.BannedTotal != want.BannedTotal ||
			stats.BannedIPList != want.BannedIPs {
			t.Errorf("GetJailStats(%s) = %+v, want %+v", want.Name, stats, want)
		}

		ips, err := s.GetBannedIPs(want.Name)
		if err != nil {
			t.Fatalf("GetBannedIPs(%s): %v", want.Name, err)
		}
		wantIPs := strings.Split(want.BannedIPs, ",")
		if len(ips) != len(wantIPs) {
			t.Fatalf("GetBannedIPs(%s) = %v, want %v", want.Name, ips, wantIPs)
		}
		for i := range wantIPs {
			if ips[i] != wantIPs[i] {
				t.Errorf("GetBannedIPs(%s)[%d] = %q, want %q", want.Name, i, ips[i], wantIPs[i])
			}
		}

		banTime, err := s.GetJailBanTime(want.Name)
		if err != nil || banTime != want.BanTime {
			t.Errorf("GetJailBanTime(%s) = %d, %v; want %d, nil", want.Name, banTime, err, want.BanTime)
		}
		findTime, err := s.GetJailFindTime(want.Name)
		if err != nil || findTime != want.FindTime {
			t.Errorf("GetJailFindTime(%s) = %d, %v; want %d, nil", want.Name, findTime, err, want.FindTime)
		}
		maxRetry, err := s.GetJailMaxRetries(want.Name)
		if err != nil || maxRetry != want.MaxRetry {
			t.Errorf("GetJailMaxRetries(%s) = %d, %v; want %d, nil", want.Name, maxRetry, err, want.MaxRetry)
		}
	}
}

func TestFakeSocketMalformedResponses(t *testing.T) {
	srv := newFakeF2BServer(t, fakeF2BFixture{Version: "1.0.2"})
	srv.SetMalformed(true)

	s, err := socket.ConnectToSocket(srv.SocketPath())
	if err != nil {
		t.Fatalf("ConnectToSocket: %v", err)
	}
	defer s.Close()

	if _, err := s.Ping(); err == nil {
		t.Error("Ping() with malformed response: want error, got nil")
	}
	if _, err := s.GetJails(); err == nil {
		t.Error("GetJails() with malformed response: want error, got nil")
	}
	if _, err := s.GetServerVersion(); err == nil {
		t.Error("GetServerVersion() with malformed response: want error, got nil")
	}
	if _, err := s.GetJailBanTime("sshd"); err == nil {
		t.Error("GetJailBanTime() with malformed response: want error, got nil")
	}
}

func TestFakeSocketRefusesConnections(t *testing.T) {
	srv := newFakeF2BServer(t, fakeF2BFixture{})
	path := srv.SocketPath()
	srv.Close()

	if _, err := socket.ConnectToSocket(path); err == nil {
		t.Error("ConnectToSocket after server Close: want error, got nil")
	}
}
