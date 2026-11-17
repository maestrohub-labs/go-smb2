package smb2

// Tests for a hostile or broken SMB server: GO-2026-5051 (out-of-bounds
// read and panic in ReadDir) and the upstream hardening ported with it.
//
// Each test drives the production code path — the real runReceiver
// goroutine and File.readdir — over a net.Pipe, reusing the fake
// connection from conn_bench_test.go. Before the fix every "hostile"
// case here panicked; a panic in runReceiver ends the whole process, so
// a regression shows up as a crashed test binary, not a quiet pass.

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/maestrohub-labs/go-smb2/internal/smb2"
	"github.com/maestrohub-labs/go-smb2/internal/utf16le"
	"github.com/stretchr/testify/require"
)

// testTimeout bounds every wait so that a hang fails the test instead of
// blocking until the go test deadline.
const testTimeout = 10 * time.Second

// rawOutput is an smb2.Encoder that writes fixed bytes.
type rawOutput []byte

func (r rawOutput) Size() int       { return len(r) }
func (r rawOutput) Encode(b []byte) { copy(b, r) }

// dirEntry builds one FILE_DIRECTORY_INFORMATION entry (MS-FSCC 2.4.10)
// for name, with NextEntryOffset set to next.
func dirEntry(name string, next uint32) []byte {
	n := utf16le.Encode(name, utf16le.MapCharsNone)
	b := make([]byte, 64+len(n))
	binary.LittleEndian.PutUint32(b[0:4], next)
	binary.LittleEndian.PutUint32(b[60:64], uint32(len(n)))
	copy(b[64:], n)
	return b
}

// serveOnce reads one request from t and writes back reply(request).
func serveOnce(t transport, reply func(req smb2.PacketCodec) []byte) {
	n, err := t.ReadSize()
	if err != nil {
		return
	}
	buf := make([]byte, n)
	if _, err := t.Read(buf); err != nil {
		return
	}
	_, _ = t.Write(reply(smb2.PacketCodec(buf)))
}

// queryDirectoryReply answers a QUERY_DIRECTORY request with listing as
// the output buffer.
func queryDirectoryReply(listing []byte) func(req smb2.PacketCodec) []byte {
	return func(req smb2.PacketCodec) []byte {
		resp := &smb2.QueryDirectoryResponse{
			PacketHeader: smb2.PacketHeader{Flags: smb2.SMB2_FLAGS_SERVER_TO_REDIR},
			Output:       rawOutput(listing),
		}
		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)
		p := smb2.PacketCodec(pkt)
		p.SetMessageId(req.MessageId())
		p.SetCreditResponse(req.CreditRequest())
		return pkt
	}
}

// headerReply answers any request with a bare 64-byte header whose
// NextCommand is next, i.e. a chained (compound) response.
func headerReply(next uint32) func(req smb2.PacketCodec) []byte {
	return func(req smb2.PacketCodec) []byte {
		pkt := make([]byte, 64)
		p := smb2.PacketCodec(pkt)
		p.SetProtocolId()
		p.SetStructureSize()
		p.SetCommand(req.Command())
		p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
		p.SetMessageId(req.MessageId())
		p.SetCreditResponse(req.CreditRequest())
		p.SetNextCommand(next)
		return pkt
	}
}

// sendAndWait sends one request through c and returns what the caller
// receives. It fails the test if the caller is left hanging.
func sendAndWait(t *testing.T, c *conn) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	req := &smb2.ReadRequest{}
	req.CreditCharge = 1
	rr, err := c.send(ctx, req)
	require.NoError(t, err)

	_, err = c.recv(rr)
	require.NotErrorIs(t, err, context.DeadlineExceeded, "the request hung instead of failing")
	return err
}

func TestReaddirRejectsOutOfBoundsEntryOffset(t *testing.T) {
	readdir := func(t *testing.T, listing []byte) ([]os.FileInfo, error) {
		t.Helper()
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		t.Cleanup(cleanup)
		c.session.Store(&session{conn: c, sessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST})

		go serveOnce(direct(serverConn), queryDirectoryReply(listing))

		f := newBenchFile(c)
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(cancel)
		f.fs.ctx = ctx
		return f.readdir("*")
	}

	// A well-formed listing must still come back whole: the bounds check
	// must not cut off real directories.
	t.Run("well-formed listing returns every entry", func(t *testing.T) {
		first := dirEntry("a.txt", 80)
		first = append(first, make([]byte, 80-len(first))...) // 8-byte aligned
		listing := append(first, dirEntry("b.txt", 0)...)

		fi, err := readdir(t, listing)
		require.NoError(t, err)
		require.Len(t, fi, 2)
		require.Equal(t, "a.txt", fi[0].Name())
		require.Equal(t, "b.txt", fi[1].Name())
	})

	hostile := []struct {
		name string
		next func(entryLen int) uint32
	}{
		// GO-2026-5051: this panicked with "slice bounds out of range".
		{"offset past the buffer", func(int) uint32 { return 0x10000 }},
		{"offset at the uint32 maximum", func(int) uint32 { return 0xFFFFFFFF }},
		// Pointing exactly at the end leaves no next entry. This was
		// already an error before the fix; it must stay one.
		{"offset at the buffer end", func(n int) uint32 { return uint32(n) }},
	}
	for _, tc := range hostile {
		t.Run(tc.name+" is an error, not a panic", func(t *testing.T) {
			entryLen := len(dirEntry("a.txt", 0))
			fi, err := readdir(t, dirEntry("a.txt", tc.next(entryLen)))
			require.Nil(t, fi)
			var ire *InvalidResponseError
			require.ErrorAs(t, err, &ire)
		})
	}
}

func TestReceiverRejectsOutOfBoundsNextCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		next uint32
	}{
		{"offset past the packet", 0x10000},
		{"offset inside the header", 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			c, cleanup := newBenchConn(clientConn)
			t.Cleanup(cleanup)

			go serveOnce(direct(serverConn), headerReply(tc.next))

			err := sendAndWait(t, c)
			var ire *InvalidResponseError
			require.ErrorAs(t, err, &ire)
			require.Contains(t, err.Error(), "NextCommand offset out of bounds")
		})
	}
}

// panicOnReadTransport panics in the receiver goroutine as soon as a
// response arrives, standing in for any decoder bug a hostile server
// might still reach.
type panicOnReadTransport struct{ transport }

func (p panicOnReadTransport) ReadSize() (int, error) {
	if _, err := p.transport.ReadSize(); err != nil {
		return 0, err
	}
	panic("injected receiver panic")
}

func TestReceiverPanicFailsRequestsInsteadOfCrashing(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	// Same wiring as newBenchConn, with the panicking transport.
	c := &conn{
		t:                   panicOnReadTransport{direct(clientConn)},
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(128),
		rdone:               make(chan struct{}, 1),
		wdone:               make(chan struct{}, 1),
		write:               make(chan []byte, 1),
		werr:                make(chan error, 1),
		dialect:             smb2.SMB302,
		maxReadSize:         bufSize,
		maxWriteSize:        bufSize,
		maxTransactSize:     bufSize,
		capabilities:        smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
	}
	go c.runSender()
	go c.runReceiver()
	t.Cleanup(func() {
		c.rdone <- struct{}{}
		_ = clientConn.Close()
	})

	go serveOnce(direct(serverConn), headerReply(0))

	err := sendAndWait(t, c)
	var ire *InvalidResponseError
	require.ErrorAs(t, err, &ire)
	require.Contains(t, err.Error(), "receiver panic")

	// The connection is marked dead, so later calls fail fast too.
	c.m.Lock()
	connErr := c.err
	c.m.Unlock()
	require.Error(t, connErr)
}
