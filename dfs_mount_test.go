package smb2

import (
	"testing"

	"github.com/maestrohub-labs/go-smb2/internal/erref"
)

func TestDFSRouter_OpPath(t *testing.T) {
	t.Run("no prefix (Case B)", func(t *testing.T) {
		d := &dfsRouter{namespacePrefix: `\srv\share`}
		for in, want := range map[string]string{
			`link\sub\f`: `link\sub\f`,
			`\link\f`:    `link\f`,
			``:           ".",
		} {
			if got := d.opPath(in); got != want {
				t.Errorf("opPath(%q)=%q, want %q", in, got, want)
			}
		}
	})
	t.Run("with prefix (Case A)", func(t *testing.T) {
		d := &dfsRouter{namespacePrefix: `\nsroot\dfs`, pathPrefix: `base\dir`}
		for in, want := range map[string]string{
			`f.csv`:     `base\dir\f.csv`,
			`sub\f.csv`: `base\dir\sub\f.csv`,
			``:          `base\dir`,
			`.`:         `base\dir`,
		} {
			if got := d.opPath(in); got != want {
				t.Errorf("opPath(%q)=%q, want %q", in, got, want)
			}
		}
	})
}

func TestDFSRouter_IsSelf(t *testing.T) {
	d := &dfsRouter{ownServer: "WINSRV", ownShare: "public"}
	cases := []struct {
		server, share string
		want          bool
	}{
		{"WINSRV", "public", true},        // exact
		{"winsrv", "PUBLIC", true},        // case-insensitive (SMB is case-insensitive)
		{"WINSRV", "backingshare", false}, // a DFS link target on the same server
		{"FILESRV", "public", false},      // different server, same share name
		{"", "", false},
	}
	for _, c := range cases {
		if got := d.isSelf(c.server, c.share); got != c.want {
			t.Errorf("isSelf(%q,%q)=%v, want %v", c.server, c.share, got, c.want)
		}
	}
}

func TestDFSRouter_FullUNC(t *testing.T) {
	d := &dfsRouter{namespacePrefix: `\nsroot\dfs`, pathPrefix: `base`}
	for in, want := range map[string]string{
		`link\f`: `\nsroot\dfs\link\f`,
		`\link`:  `\nsroot\dfs\link`,
		``:       `\nsroot\dfs`,
		`.`:      `\nsroot\dfs`,
	} {
		if got := d.fullUNC(in); got != want {
			t.Errorf("fullUNC(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestIsIPCShare(t *testing.T) {
	for in, want := range map[string]bool{
		`\\server\IPC$`:  true,
		`\\server\ipc$`:  true,
		`\\server\IPC$\`: true,
		`\\server\share`: false,
		`\\server\data`:  false,
	} {
		if got := isIPCShare(in); got != want {
			t.Errorf("isIPCShare(%q)=%v, want %v", in, got, want)
		}
	}
}

func TestIsPathNotCovered(t *testing.T) {
	if !isPathNotCovered(&ResponseError{Code: uint32(erref.STATUS_PATH_NOT_COVERED)}) {
		t.Error("PATH_NOT_COVERED not detected")
	}
	if isPathNotCovered(&ResponseError{Code: uint32(erref.STATUS_BAD_NETWORK_NAME)}) {
		t.Error("BAD_NETWORK_NAME wrongly matched as path-not-covered")
	}
}

func TestIsDFSResolvable(t *testing.T) {
	for _, code := range []erref.NtStatus{
		erref.STATUS_BAD_NETWORK_NAME,
		erref.STATUS_PATH_NOT_COVERED,
		erref.STATUS_DFS_UNAVAILABLE,
	} {
		if !isDFSResolvable(&ResponseError{Code: uint32(code)}) {
			t.Errorf("%v should be DFS-resolvable", code)
		}
	}
	if isDFSResolvable(&ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)}) {
		t.Error("ACCESS_DENIED must not be treated as DFS-resolvable")
	}
}
