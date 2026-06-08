package smb2

import (
	"context"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/maestrohub-labs/go-smb2/internal/dfsc"
	"github.com/maestrohub-labs/go-smb2/internal/erref"
)

func TestUNCHelpers(t *testing.T) {
	t.Run("normUNC", func(t *testing.T) {
		for in, want := range map[string]string{
			`\\srv\share`:  `\srv\share`,
			`srv\share`:    `\srv\share`,
			`/srv/share`:   `\srv\share`,
			`\srv\share`:   `\srv\share`,
			`\\srv\share\`: `\srv\share\`,
		} {
			if got := normUNC(in); got != want {
				t.Errorf("normUNC(%q)=%q, want %q", in, got, want)
			}
		}
	})
	t.Run("splitUNC", func(t *testing.T) {
		s, sh, rel := splitUNC(`\backing\share\dir\file.csv`)
		if s != "backing" || sh != "share" || rel != `dir\file.csv` {
			t.Errorf("splitUNC = (%q,%q,%q)", s, sh, rel)
		}
		s, sh, rel = splitUNC(`\backing\share`)
		if s != "backing" || sh != "share" || rel != "" {
			t.Errorf("splitUNC bare share = (%q,%q,%q)", s, sh, rel)
		}
	})
	t.Run("serverFromUNC", func(t *testing.T) {
		if got := serverFromUNC(`\\backing\share\x`); got != "backing" {
			t.Errorf("serverFromUNC=%q", got)
		}
	})
}

func TestUTF16PrefixSuffix(t *testing.T) {
	// ASCII path: byte count and char count agree.
	unc := `\ns\dfs\link\sub\file.csv`
	prefix := `\ns\dfs\link`
	consumed := uint16(len(utf16.Encode([]rune(prefix))) * 2)
	if got := utf16Prefix(unc, consumed); got != prefix {
		t.Errorf("utf16Prefix=%q, want %q", got, prefix)
	}
	if got := utf16Suffix(unc, consumed); got != `\sub\file.csv` {
		t.Errorf("utf16Suffix=%q, want %q", got, `\sub\file.csv`)
	}

	// Non-ASCII: a multi-byte rune must not throw off the split — the
	// classic byte-vs-char off-by-two bug (gotcha #11).
	unc2 := `\ns\café\file`
	pre2 := `\ns\café`
	consumed2 := uint16(len(utf16.Encode([]rune(pre2))) * 2)
	if got := utf16Prefix(unc2, consumed2); got != pre2 {
		t.Errorf("utf16Prefix(non-ascii)=%q, want %q", got, pre2)
	}
	if got := utf16Suffix(unc2, consumed2); got != `\file` {
		t.Errorf("utf16Suffix(non-ascii)=%q, want %q", got, `\file`)
	}
}

// newTestResolver builds a resolver whose hop loop is driven by fetch,
// with no backing-conn map (conns is unused when fetch is overridden).
func newTestResolver(fetch func(ctx context.Context, server, unc string) (*dfsc.ReferralResponse, error)) *dfsResolver {
	return &dfsResolver{
		cache: newReferralCache(),
		logf:  func(string, ...any) {},
		fetch: fetch,
	}
}

func storageResp(consumedPrefix, target string) *dfsc.ReferralResponse {
	return &dfsc.ReferralResponse{
		PathConsumed: uint16(len(utf16.Encode([]rune(consumedPrefix))) * 2),
		HeaderFlags:  dfsc.HeaderFlagStorageServers,
		Referrals:    []dfsc.Referral{{Version: 4, ServerType: dfsc.ServerTypeLink, TTL: 300 * time.Second, Path: consumedPrefix, TargetUNC: target}},
	}
}

func TestResolve_SingleLink(t *testing.T) {
	calls := 0
	r := newTestResolver(func(_ context.Context, server, unc string) (*dfsc.ReferralResponse, error) {
		calls++
		if server != "ns" {
			t.Fatalf("unexpected server %q", server)
		}
		return storageResp(`\ns\dfs\link`, `\backing\share`), nil
	})

	srv, sh, rel, err := r.resolve(context.Background(), `\ns\dfs\link\sub\file.csv`)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if srv != "backing" || sh != "share" || rel != `sub\file.csv` {
		t.Fatalf("resolve = (%q,%q,%q)", srv, sh, rel)
	}

	// Second resolve must be served from cache (no new fetch).
	if _, _, _, err := r.resolve(context.Background(), `\ns\dfs\link\other.csv`); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if calls != 1 {
		t.Errorf("fetch called %d times, want 1 (cache miss only)", calls)
	}
}

// rootResp models a real Windows DFS *root* referral: ServerType=ROOT and,
// per [MS-DFSC], the StorageServers header flag IS set (the root targets are
// servers you connect to). The crux of the Case-A bug: storage-set must NOT
// be mistaken for "terminal" when path remains below the root.
func rootResp(consumedPrefix, target string) *dfsc.ReferralResponse {
	return &dfsc.ReferralResponse{
		PathConsumed: uint16(len(utf16.Encode([]rune(consumedPrefix))) * 2),
		HeaderFlags:  dfsc.HeaderFlagReferralServers | dfsc.HeaderFlagStorageServers,
		Referrals:    []dfsc.Referral{{Version: 4, ServerType: dfsc.ServerTypeRoot, TTL: 900 * time.Second, Path: consumedPrefix, TargetUNC: target}},
	}
}

// TestResolve_NamespaceFrontEnd_DeepLink is the issue-2431 production shape:
// host is the DFS namespace front end (e.g. \10.176.0.40\Data) whose root
// referral carries the StorageServers flag, and the requested path crosses a
// DFS link below the root. Resolution must connect to the root target and
// issue a SECOND (link) referral there — not stop at the root.
func TestResolve_NamespaceFrontEnd_DeepLink(t *testing.T) {
	calls := map[string]int{}
	r := newTestResolver(func(_ context.Context, server, unc string) (*dfsc.ReferralResponse, error) {
		calls[server]++
		switch server {
		case "nsfront": // namespace front end: returns a ROOT referral
			return rootResp(`\nsfront\Data`, `\roottgt\Data`), nil
		case "roottgt": // root target: resolves the CKY link to storage
			return storageResp(`\roottgt\Data\CKY`, `\backing2\share2`), nil
		default:
			t.Fatalf("unexpected server %q (unc %q)", server, unc)
			return nil, nil
		}
	})

	srv, sh, rel, err := r.resolve(context.Background(), `\nsfront\Data\CKY\Departments`)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if srv != "backing2" || sh != "share2" || rel != "Departments" {
		t.Fatalf("resolve = (%q,%q,%q), want backing2/share2/Departments", srv, sh, rel)
	}
	if calls["nsfront"] != 1 || calls["roottgt"] != 1 {
		t.Fatalf("fetch calls = %v, want one each to nsfront and roottgt", calls)
	}
}

// TestResolve_BareRootThenDeepLink guards against cache poisoning: resolving
// the bare namespace root first (terminal — just connect to the root target)
// must NOT cache the root mapping as a terminal LINK. A later deep-link
// resolve that reuses the cached root entry must still issue the link
// referral at the root target rather than short-circuit on the cache.
func TestResolve_BareRootThenDeepLink(t *testing.T) {
	calls := map[string]int{}
	r := newTestResolver(func(_ context.Context, server, unc string) (*dfsc.ReferralResponse, error) {
		calls[server]++
		switch server {
		case "nsfront":
			return rootResp(`\nsfront\Data`, `\roottgt\Data`), nil
		case "roottgt":
			return storageResp(`\roottgt\Data\CKY`, `\backing2\share2`), nil
		default:
			t.Fatalf("unexpected server %q (unc %q)", server, unc)
			return nil, nil
		}
	})

	// Case-A mount: bare root resolves to the root target (terminal connect).
	srv, sh, rel, err := r.resolve(context.Background(), `\nsfront\Data`)
	if err != nil {
		t.Fatalf("bare-root resolve: %v", err)
	}
	if srv != "roottgt" || sh != "Data" || rel != "" {
		t.Fatalf("bare-root resolve = (%q,%q,%q), want roottgt/Data/<empty>", srv, sh, rel)
	}

	// Deep path below the same root must still follow the link, reusing the
	// cached root mapping for the front end but querying roottgt for the link.
	srv, sh, rel, err = r.resolve(context.Background(), `\nsfront\Data\CKY\Departments`)
	if err != nil {
		t.Fatalf("deep resolve: %v", err)
	}
	if srv != "backing2" || sh != "share2" || rel != "Departments" {
		t.Fatalf("deep resolve = (%q,%q,%q), want backing2/share2/Departments", srv, sh, rel)
	}
	// nsfront queried once (root cached and reused); roottgt queried once.
	if calls["nsfront"] != 1 {
		t.Errorf("nsfront fetched %d times, want 1 (root mapping cached)", calls["nsfront"])
	}
	if calls["roottgt"] != 1 {
		t.Errorf("roottgt fetched %d times, want 1", calls["roottgt"])
	}
}

func TestResolve_Interlink_TwoHops(t *testing.T) {
	r := newTestResolver(func(_ context.Context, server, unc string) (*dfsc.ReferralResponse, error) {
		switch server {
		case "ns":
			// Root referral (no StorageServers flag) -> another namespace.
			return &dfsc.ReferralResponse{
				PathConsumed: uint16(len(utf16.Encode([]rune(`\ns\dfs\link`))) * 2),
				HeaderFlags:  dfsc.HeaderFlagReferralServers,
				Referrals:    []dfsc.Referral{{Version: 4, ServerType: dfsc.ServerTypeRoot, Path: `\ns\dfs\link`, TargetUNC: `\ns2\dfs2`}},
			}, nil
		case "ns2":
			return storageResp(`\ns2\dfs2`, `\backing\share`), nil
		default:
			t.Fatalf("unexpected server %q", server)
			return nil, nil
		}
	})

	srv, sh, rel, err := r.resolve(context.Background(), `\ns\dfs\link\sub\file.csv`)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if srv != "backing" || sh != "share" || rel != `sub\file.csv` {
		t.Fatalf("resolve = (%q,%q,%q)", srv, sh, rel)
	}
}

func TestResolve_NotDFS_UsesPathAsIs(t *testing.T) {
	r := newTestResolver(func(_ context.Context, server, unc string) (*dfsc.ReferralResponse, error) {
		return nil, &ResponseError{Code: uint32(erref.STATUS_NOT_FOUND)}
	})
	srv, sh, rel, err := r.resolve(context.Background(), `\plain\share\dir\f.csv`)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if srv != "plain" || sh != "share" || rel != `dir\f.csv` {
		t.Fatalf("resolve = (%q,%q,%q), want path used as-is", srv, sh, rel)
	}
}

func TestResolve_LoopDetected(t *testing.T) {
	// A root referral that maps back onto a server which refers to the
	// first again forms a cycle; resolve must bail with an error rather
	// than spin to the hop cap silently.
	r := newTestResolver(func(_ context.Context, server, unc string) (*dfsc.ReferralResponse, error) {
		switch server {
		case "a":
			return &dfsc.ReferralResponse{
				PathConsumed: uint16(len(utf16.Encode([]rune(`\a\ns`))) * 2),
				HeaderFlags:  dfsc.HeaderFlagReferralServers,
				Referrals:    []dfsc.Referral{{Version: 4, ServerType: dfsc.ServerTypeRoot, Path: `\a\ns`, TargetUNC: `\b\ns`}},
			}, nil
		case "b":
			return &dfsc.ReferralResponse{
				PathConsumed: uint16(len(utf16.Encode([]rune(`\b\ns`))) * 2),
				HeaderFlags:  dfsc.HeaderFlagReferralServers,
				Referrals:    []dfsc.Referral{{Version: 4, ServerType: dfsc.ServerTypeRoot, Path: `\b\ns`, TargetUNC: `\a\ns`}},
			}, nil
		default:
			return nil, &ResponseError{Code: uint32(erref.STATUS_NOT_FOUND)}
		}
	})
	if _, _, _, err := r.resolve(context.Background(), `\a\ns\x`); err == nil {
		t.Fatal("expected a loop error")
	}
}
