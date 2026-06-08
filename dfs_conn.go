package smb2

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
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
}

func newBackingConns(origin *Session) *backingConns {
	return &backingConns{origin: origin, conns: make(map[string]*Session)}
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

// close logs off every backing session. The origin session is not touched
// — it is owned by the caller that created the resolver.
func (b *backingConns) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for key, s := range b.conns {
		_ = s.Logoff()
		delete(b.conns, key)
	}
}
