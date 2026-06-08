package dfsc

import (
	"testing"
	"time"
	"unicode/utf16"
)

// TestDecode_V3_GoldenLiteral decodes a hand-assembled, byte-for-byte
// RESP_GET_DFS_REFERRAL with a single v3 target entry. Offsets and sizes
// are annotated inline so the expected layout is independently
// verifiable from the spec without running the encoder helper below.
func TestDecode_V3_GoldenLiteral(t *testing.T) {
	raw := []byte{
		// ---- RESP_GET_DFS_REFERRAL header (8 bytes) ----
		0x08, 0x00, // PathConsumed   = 8 bytes  (= 4 UTF-16 chars: `\a\b`)
		0x01, 0x00, // NumberOfReferrals = 1
		0x02, 0x00, 0x00, 0x00, // ReferralHeaderFlags = 0x2 (StorageServers)

		// ---- referral entry #0 (v3 target), starts at offset 8 ----
		0x03, 0x00, // VersionNumber = 3
		0x36, 0x00, // Size = 54
		0x00, 0x00, // ServerType = 0 (link/leaf)
		0x00, 0x00, // ReferralEntryFlags = 0
		0x58, 0x02, 0x00, 0x00, // TimeToLive = 600 s
		0x22, 0x00, // DFSPathOffset = 34 (entry-relative)
		0x00, 0x00, // DFSAlternatePathOffset = 0 (absent)
		0x2C, 0x00, // NetworkAddressOffset = 44 (entry-relative)
		// ServiceSiteGuid (16 bytes, ignored)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// offset 34: DFSPath = `\a\b` + NUL
		0x5C, 0x00, 0x61, 0x00, 0x5C, 0x00, 0x62, 0x00, 0x00, 0x00,
		// offset 44: NetworkAddress = `\x\y` + NUL
		0x5C, 0x00, 0x78, 0x00, 0x5C, 0x00, 0x79, 0x00, 0x00, 0x00,
	}

	resp, err := DecodeReferralResponse(raw)
	if err != nil {
		t.Fatalf("DecodeReferralResponse: %v", err)
	}
	if resp.PathConsumed != 8 {
		t.Errorf("PathConsumed = %d, want 8", resp.PathConsumed)
	}
	if resp.HeaderFlags != HeaderFlagStorageServers {
		t.Errorf("HeaderFlags = %#x, want %#x", resp.HeaderFlags, HeaderFlagStorageServers)
	}
	if len(resp.Referrals) != 1 {
		t.Fatalf("got %d referrals, want 1", len(resp.Referrals))
	}
	r := resp.Referrals[0]
	if r.Version != 3 {
		t.Errorf("Version = %d, want 3", r.Version)
	}
	if r.ServerType != ServerTypeLink {
		t.Errorf("ServerType = %d, want link(0)", r.ServerType)
	}
	if r.TTL != 600*time.Second {
		t.Errorf("TTL = %v, want 600s", r.TTL)
	}
	if r.Path != `\a\b` {
		t.Errorf("Path = %q, want %q", r.Path, `\a\b`)
	}
	if r.AltPath != "" {
		t.Errorf("AltPath = %q, want empty", r.AltPath)
	}
	if r.TargetUNC != `\x\y` {
		t.Errorf("TargetUNC = %q, want %q", r.TargetUNC, `\x\y`)
	}
}

// TestDecode_V4_MultiReferral builds a two-entry v4 response with the
// spec-faithful encoder helper and checks the PathConsumed split plus
// both decoded targets. The DFSPath spans `\ns\dfs\link` so PathConsumed
// is set to its byte length to model a real link crossing.
func TestDecode_V4_MultiReferral(t *testing.T) {
	dfsPath := `\ns\dfs\link`
	consumed := uint16(len(utf16.Encode([]rune(dfsPath))) * 2)

	raw := buildResponse(consumed, HeaderFlagStorageServers|HeaderFlagTargetFailback,
		v4Target(0x0000, 0, 300, dfsPath, "", `\backing\share`),
		v4Target(0x0000, 0, 300, dfsPath, "", `\backing2\share`),
	)

	resp, err := DecodeReferralResponse(raw)
	if err != nil {
		t.Fatalf("DecodeReferralResponse: %v", err)
	}
	if resp.PathConsumed != consumed {
		t.Errorf("PathConsumed = %d, want %d", resp.PathConsumed, consumed)
	}
	if int(resp.PathConsumed)/2 != len([]rune(dfsPath)) {
		t.Errorf("PathConsumed/2 = %d chars, want %d (off-by-two byte/char bug)",
			int(resp.PathConsumed)/2, len([]rune(dfsPath)))
	}
	if len(resp.Referrals) != 2 {
		t.Fatalf("got %d referrals, want 2", len(resp.Referrals))
	}
	if resp.Referrals[0].TargetUNC != `\backing\share` {
		t.Errorf("referral[0].TargetUNC = %q", resp.Referrals[0].TargetUNC)
	}
	if resp.Referrals[1].TargetUNC != `\backing2\share` {
		t.Errorf("referral[1].TargetUNC = %q", resp.Referrals[1].TargetUNC)
	}
	for i, r := range resp.Referrals {
		if r.Version != 4 {
			t.Errorf("referral[%d].Version = %d, want 4", i, r.Version)
		}
		if r.Path != dfsPath {
			t.Errorf("referral[%d].Path = %q, want %q", i, r.Path, dfsPath)
		}
		if r.TTL != 300*time.Second {
			t.Errorf("referral[%d].TTL = %v, want 300s", i, r.TTL)
		}
	}
}

// TestDecode_V4_RootReferral confirms ServerType is surfaced so the
// resolver can distinguish a root (namespace) referral from a leaf.
func TestDecode_V4_RootReferral(t *testing.T) {
	raw := buildResponse(0, HeaderFlagReferralServers,
		v4Target(ServerTypeRoot, 0, 900, `\ns\dfs`, "", `\rootsrv\dfs`),
	)
	resp, err := DecodeReferralResponse(raw)
	if err != nil {
		t.Fatalf("DecodeReferralResponse: %v", err)
	}
	if len(resp.Referrals) != 1 {
		t.Fatalf("got %d referrals, want 1", len(resp.Referrals))
	}
	if !resp.Referrals[0].IsRootTarget() {
		t.Errorf("IsRootTarget() = false, want true (ServerType=%d)", resp.Referrals[0].ServerType)
	}
}

// TestDecode_V4_PooledStrings models the REAL Windows RESP_GET_DFS_REFERRAL
// layout, which the other encoder helper (v4Target) does not: each fixed
// referral entry's Size field covers ONLY the 34-byte fixed header, and all
// the DFSPath / NetworkAddress strings live in one shared pool that follows
// every fixed entry. The entry-relative string offsets therefore point well
// past (entryStart + Size).
//
// This is the exact shape captured from Windows Server (Size=34,
// NetworkAddressOffset=114). The previous decoder clamped string reads to the
// entry's Size, so it returned an empty TargetUNC here — which made the DFS
// resolver find no usable target and silently treat every link as "not
// covered." This test pins the pooled-string layout so that regression cannot
// recur. (See rule 31: test against the production wire format, not a
// convenient stand-in.)
func TestDecode_V4_PooledStrings(t *testing.T) {
	dfsPath := `\WINSRV\public\link`
	consumed := uint16(len(utf16.Encode([]rune(dfsPath))) * 2)
	raw := buildResponsePooledV4(consumed, HeaderFlagStorageServers,
		v4Spec{serverType: ServerTypeLink, ttl: 300, dfsPath: dfsPath, netAddr: `\WINSRV\backingshare`},
	)

	resp, err := DecodeReferralResponse(raw)
	if err != nil {
		t.Fatalf("DecodeReferralResponse: %v", err)
	}
	if len(resp.Referrals) != 1 {
		t.Fatalf("got %d referrals, want 1", len(resp.Referrals))
	}
	r := resp.Referrals[0]
	if r.TargetUNC != `\WINSRV\backingshare` {
		t.Errorf("TargetUNC = %q, want %q (string offset points past entry Size into the shared pool)",
			r.TargetUNC, `\WINSRV\backingshare`)
	}
	if r.Path != dfsPath {
		t.Errorf("Path = %q, want %q", r.Path, dfsPath)
	}
	if r.TTL != 300*time.Second {
		t.Errorf("TTL = %v, want 300s", r.TTL)
	}
}

// TestDecode_V4_PooledStrings_Multi covers two entries sharing one trailing
// string pool — the offsets of entry #1's strings are relative to entry #1's
// start but point past both fixed headers.
func TestDecode_V4_PooledStrings_Multi(t *testing.T) {
	raw := buildResponsePooledV4(12, HeaderFlagStorageServers,
		v4Spec{serverType: ServerTypeLink, ttl: 300, dfsPath: `\a\b\c`, netAddr: `\srv1\sh1`},
		v4Spec{serverType: ServerTypeLink, ttl: 300, dfsPath: `\a\b\c`, netAddr: `\srv2\sh2longer`},
	)

	resp, err := DecodeReferralResponse(raw)
	if err != nil {
		t.Fatalf("DecodeReferralResponse: %v", err)
	}
	if len(resp.Referrals) != 2 {
		t.Fatalf("got %d referrals, want 2", len(resp.Referrals))
	}
	if got := resp.Referrals[0].TargetUNC; got != `\srv1\sh1` {
		t.Errorf("referral[0].TargetUNC = %q, want %q", got, `\srv1\sh1`)
	}
	if got := resp.Referrals[1].TargetUNC; got != `\srv2\sh2longer` {
		t.Errorf("referral[1].TargetUNC = %q, want %q", got, `\srv2\sh2longer`)
	}
}

func TestDecode_Errors(t *testing.T) {
	t.Run("short header", func(t *testing.T) {
		if _, err := DecodeReferralResponse([]byte{0, 0, 1}); err == nil {
			t.Fatal("expected error on short header")
		}
	})
	t.Run("truncated entry", func(t *testing.T) {
		// header claims 1 referral but no entry bytes follow.
		raw := []byte{0, 0, 0x01, 0, 0, 0, 0, 0}
		if _, err := DecodeReferralResponse(raw); err == nil {
			t.Fatal("expected error on truncated entry")
		}
	})
	t.Run("zero referrals", func(t *testing.T) {
		raw := []byte{0x10, 0, 0x00, 0, 0x02, 0, 0, 0}
		resp, err := DecodeReferralResponse(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Referrals) != 0 || resp.PathConsumed != 16 {
			t.Fatalf("got %+v", resp)
		}
	})
}

// ---- spec-faithful encoder helpers (test-only) ----

// utf16z returns s as null-terminated UTF-16LE bytes.
func utf16z(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2+2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return append(b, 0, 0)
}

func u16(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }
func u32(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }

// v4Target encodes a normal (non-NameList) v4 referral entry per
// [MS-DFSC] 2.2.5.4: 18-byte fixed header + 16-byte ServiceSiteGuid +
// packed string area, with the three string offsets entry-relative.
func v4Target(serverType, entryFlags uint16, ttl uint32, dfsPath, altPath, netAddr string) []byte {
	const fixed = 18 + 16 // through ServiceSiteGuid

	dfsB := utf16z(dfsPath)
	netB := utf16z(netAddr)
	var altB []byte
	altOff := uint16(0)
	if altPath != "" {
		altB = utf16z(altPath)
	}

	// Lay strings out after the fixed header: DFSPath, [AltPath], NetAddr.
	dfsOff := uint16(fixed)
	cur := fixed + len(dfsB)
	if altPath != "" {
		altOff = uint16(cur)
		cur += len(altB)
	}
	netOff := uint16(cur)
	size := uint16(cur + len(netB))

	e := make([]byte, 0, size)
	e = append(e, u16(4)...)           // VersionNumber
	e = append(e, u16(size)...)        // Size
	e = append(e, u16(serverType)...)  // ServerType
	e = append(e, u16(entryFlags)...)  // ReferralEntryFlags
	e = append(e, u32(ttl)...)         // TimeToLive
	e = append(e, u16(dfsOff)...)      // DFSPathOffset
	e = append(e, u16(altOff)...)      // DFSAlternatePathOffset
	e = append(e, u16(netOff)...)      // NetworkAddressOffset
	e = append(e, make([]byte, 16)...) // ServiceSiteGuid
	e = append(e, dfsB...)
	if altPath != "" {
		e = append(e, altB...)
	}
	e = append(e, netB...)
	return e
}

// v4Spec describes a v4 target entry for the pooled-string encoder.
type v4Spec struct {
	serverType, entryFlags    uint16
	ttl                       uint32
	dfsPath, altPath, netAddr string
}

// buildResponsePooledV4 assembles a RESP_GET_DFS_REFERRAL the way Windows
// actually frames it: every fixed referral-entry header (Size = 34, the fixed
// portion only) is emitted first, contiguously, and ALL strings follow in one
// shared pool. Each entry's string offsets are entry-relative (per [MS-DFSC])
// but resolve into the trailing pool, i.e. they exceed the entry's own Size.
// This is the layout v4Target (above) does NOT model.
func buildResponsePooledV4(pathConsumed uint16, headerFlags uint32, specs ...v4Spec) []byte {
	const fixed = 34 // v4 fixed header through ServiceSiteGuid
	const hdr = 8
	n := len(specs)
	poolStart := hdr + n*fixed

	// Lay all strings into the shared pool, recording absolute offsets.
	var pool []byte
	abs := func(s string) uint16 {
		off := uint16(poolStart + len(pool))
		pool = append(pool, utf16z(s)...)
		return off
	}
	type offs struct{ dfs, alt, net uint16 }
	o := make([]offs, n)
	for i, sp := range specs {
		o[i].dfs = abs(sp.dfsPath)
		if sp.altPath != "" {
			o[i].alt = abs(sp.altPath)
		}
		o[i].net = abs(sp.netAddr)
	}

	b := make([]byte, 0, poolStart+len(pool))
	b = append(b, u16(pathConsumed)...)
	b = append(b, u16(uint16(n))...)
	b = append(b, u32(headerFlags)...)
	for i, sp := range specs {
		entryStart := hdr + i*fixed
		rel := func(absOff uint16) uint16 {
			if absOff == 0 {
				return 0
			}
			return absOff - uint16(entryStart)
		}
		b = append(b, u16(4)...)             // VersionNumber
		b = append(b, u16(fixed)...)         // Size = fixed header only
		b = append(b, u16(sp.serverType)...) // ServerType
		b = append(b, u16(sp.entryFlags)...) // ReferralEntryFlags
		b = append(b, u32(sp.ttl)...)        // TimeToLive
		b = append(b, u16(rel(o[i].dfs))...) // DFSPathOffset (entry-relative)
		b = append(b, u16(rel(o[i].alt))...) // DFSAlternatePathOffset
		b = append(b, u16(rel(o[i].net))...) // NetworkAddressOffset
		b = append(b, make([]byte, 16)...)   // ServiceSiteGuid
	}
	b = append(b, pool...)
	return b
}

// buildResponse assembles a RESP_GET_DFS_REFERRAL from pre-encoded entries.
func buildResponse(pathConsumed uint16, headerFlags uint32, entries ...[]byte) []byte {
	b := make([]byte, 0, 8)
	b = append(b, u16(pathConsumed)...)
	b = append(b, u16(uint16(len(entries)))...)
	b = append(b, u32(headerFlags)...)
	for _, e := range entries {
		b = append(b, e...)
	}
	return b
}
