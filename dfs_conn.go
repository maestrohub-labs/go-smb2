package smb2

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/maestrohub-labs/go-smb2/internal/utf16le"
)

// dfsPort is the port DFS referrals are always resolved on. Referrals are
// name-based and assume the standard SMB port; a referral never carries a
// port, so backing servers are always dialed on 445.
const dfsPort = "445"

// backingConns owns the SMB sessions to DFS backing servers named in
// referrals. One session per server is dialed on demand (with the origin
// session's Dialer, so auth/negotiator settings match) and reused across
// operations until close.
type backingConns struct {
	origin *Session // session whose Dialer is reused; never owned/closed here

	mu    sync.Mutex
	conns map[string]*Session // key: strings.ToLower(server)

	sharesMu sync.Mutex
	shares   map[string]*Share // key: strings.ToLower(server + "\\" + share)
}

func newBackingConns(origin *Session) *backingConns {
	return &backingConns{
		origin: origin,
		conns:  make(map[string]*Session),
		shares: make(map[string]*Share),
	}
}

// shareFor returns a tree connect to \\server\share on the backing
// session, mounting and caching it on first use. The returned share has
// no DFS router of its own: it is reached only via createFile retries
// whose paths are already fully resolved, so it needs no further routing.
func (b *backingConns) shareFor(ctx context.Context, server, share string, mapping utf16le.MapChars) (*Share, error) {
	key := strings.ToLower(server + `\` + share)

	b.sharesMu.Lock()
	if fs, ok := b.shares[key]; ok {
		b.sharesMu.Unlock()
		return fs, nil
	}
	b.sharesMu.Unlock()

	sess, err := b.sessionFor(ctx, server)
	if err != nil {
		return nil, err
	}
	fs, err := sess.mountRaw(fmt.Sprintf(`\\%s\%s`, server, share), mapping)
	if err != nil {
		return nil, fmt.Errorf("dfs: mount backing \\\\%s\\%s: %w", server, share, err)
	}

	b.sharesMu.Lock()
	if existing, ok := b.shares[key]; ok {
		// Lost a race; reuse the winner and drop our duplicate.
		b.sharesMu.Unlock()
		_ = fs.Umount()
		return existing, nil
	}
	b.shares[key] = fs
	b.sharesMu.Unlock()
	return fs, nil
}

// sessionFor returns a session connected to server on port 445. If server
// is the origin server the origin session is returned (no second dial).
// Otherwise a cached session is reused, or a new one is dialed with the
// origin's Dialer and cached.
func (b *backingConns) sessionFor(ctx context.Context, server string) (*Session, error) {
	if strings.EqualFold(server, b.origin.serverName()) {
		return b.origin, nil
	}

	key := strings.ToLower(server)

	b.mu.Lock()
	defer b.mu.Unlock()

	if s, ok := b.conns[key]; ok {
		return s, nil
	}

	d := b.origin.dialer
	s, err := d.Dial(ctx, net.JoinHostPort(server, dfsPort))
	if err != nil {
		return nil, fmt.Errorf("dfs: dial backing server %s: %w", server, err)
	}
	b.conns[key] = s
	return s, nil
}

// close umounts cached backing shares and logs off every backing
// session. The origin session is not touched — it is owned by the caller
// that created the resolver. close is idempotent.
func (b *backingConns) close() {
	b.sharesMu.Lock()
	for key, fs := range b.shares {
		_ = fs.Umount()
		delete(b.shares, key)
	}
	b.sharesMu.Unlock()

	b.mu.Lock()
	for key, s := range b.conns {
		_ = s.Logoff()
		delete(b.conns, key)
	}
	b.mu.Unlock()
}
