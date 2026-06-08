package smb2

import (
	"context"
	"errors"
	"strings"

	"github.com/maestrohub-labs/go-smb2/internal/erref"
	"github.com/maestrohub-labs/go-smb2/internal/smb2"
	"github.com/maestrohub-labs/go-smb2/internal/utf16le"
)

// dfsRouter carries transparent-DFS state for a top-level Share. It maps
// share-relative operation names to (a) the path actually sent to the
// underlying tree connect and (b) the namespace UNC used to re-resolve a
// referral when the server reports the path crossed a DFS link.
type dfsRouter struct {
	resolver *dfsResolver
	// namespacePrefix is the UNC this share represents (e.g. `\server\share`
	// for a plain mount, or the originally-requested `\nsroot\dfs` for a
	// Case-A namespace-root mount). Operation names append to it to form
	// the full UNC for referral resolution.
	namespacePrefix string
	// pathPrefix is prepended to operation names before they are sent to
	// the underlying tree connect. Non-empty only for a Case-A mount whose
	// backing target sits below the backing share root.
	pathPrefix string
}

// opPath joins the share-relative op name with the Case-A path prefix to
// get the path to send to the backing tree connect.
func (d *dfsRouter) opPath(name string) string {
	name = strings.TrimLeft(name, `\/`)
	if d.pathPrefix == "" {
		if name == "" {
			return "."
		}
		return name
	}
	if name == "" || name == "." {
		return d.pathPrefix
	}
	return d.pathPrefix + `\` + name
}

// fullUNC builds the namespace-side UNC for an op name, for referral
// resolution.
func (d *dfsRouter) fullUNC(name string) string {
	name = strings.TrimLeft(name, `\/`)
	if name == "" || name == "." {
		return d.namespacePrefix
	}
	return d.namespacePrefix + `\` + name
}

// attachDFS wires a freshly tree-connected Share with DFS routing.
func attachDFS(fs *Share, r *dfsResolver, namespaceUNC, pathPrefix string, ownsResolver bool) {
	fs.dfs = &dfsRouter{
		resolver:        r,
		namespacePrefix: normUNC(namespaceUNC),
		pathPrefix:      pathPrefix,
	}
	fs.ownsResolver = ownsResolver
}

// dfsMount handles Case A: the requested share is a DFS namespace root (or
// otherwise not covered by this server), so treeConnect failed. It
// resolves the referral and mounts the backing target, returning a share
// whose operations are transparently prefixed with the backing-relative
// path. On any resolution failure it returns the original mount error so
// the caller sees the real cause rather than a DFS artifact.
func (c *Session) dfsMount(sharename string, mapping utf16le.MapChars, origErr error) (*Share, error) {
	r := newDFSResolver(c)
	c.warnIfNoDFSCap(r)

	server, share, rel, err := r.resolve(c.ctx, sharename)
	if err != nil || share == "" {
		r.close()
		return nil, origErr
	}

	backing, err := r.conns.shareFor(c.ctx, server, share, mapping)
	if err != nil {
		r.close()
		return nil, origErr
	}

	// Return a distinct share view that owns the resolver and prepends the
	// backing-relative prefix; the cached backing share itself stays
	// prefix-free for reuse by mid-op retries.
	fs := &Share{treeConn: backing.treeConn, ctx: context.Background(), mapping: mapping}
	attachDFS(fs, r, sharename, rel, true)
	return fs, nil
}

// createFile is the DFS-aware wrapper over createFileRaw. For a non-DFS
// share it is a straight passthrough. For a DFS share it marks the request
// as a DFS operation, applies any Case-A path prefix, and — if the server
// reports the path crossed a DFS link — resolves the referral once and
// retries the CREATE against the backing target.
func (fs *Share) createFile(name string, req *smb2.CreateRequest, followSymlinks bool) (*File, error) {
	if fs.dfs == nil {
		return fs.createFileRaw(name, req, followSymlinks)
	}

	req.Header().Flags |= smb2.SMB2_FLAGS_DFS_OPERATIONS

	f, err := fs.createFileRaw(fs.dfs.opPath(name), req, followSymlinks)
	if err == nil || !isPathNotCovered(err) {
		return f, err
	}

	// The path crosses a DFS link. resolve() follows the whole referral
	// chain to a terminal storage target, so the retry lands on a plain
	// backing share and needs no further DFS recursion.
	bf, berr := fs.dfsResolveAndCreate(name, req, followSymlinks)
	if berr != nil {
		// Keep the original PATH_NOT_COVERED; the DFS attempt is best
		// effort and the real failure is more informative.
		return nil, err
	}
	return bf, nil
}

// dfsResolveAndCreate resolves the referral for name and reissues the
// CREATE against the resolved backing share.
func (fs *Share) dfsResolveAndCreate(name string, req *smb2.CreateRequest, followSymlinks bool) (*File, error) {
	server, share, rel, err := fs.dfs.resolver.resolve(fs.ctx, fs.dfs.fullUNC(name))
	if err != nil {
		return nil, err
	}
	backing, err := fs.dfs.resolver.conns.shareFor(fs.ctx, server, share, fs.mapping)
	if err != nil {
		return nil, err
	}
	relName := rel
	if relName == "" {
		relName = "."
	}
	return backing.WithContext(fs.ctx).createFileRaw(relName, req, followSymlinks)
}

// mountRaw tree-connects to sharename and returns a plain Share with no
// DFS routing. Used for DFS backing targets, whose paths are already
// fully resolved.
func (c *Session) mountRaw(sharename string, mapping utf16le.MapChars) (*Share, error) {
	tc, err := treeConnect(c.ctx, c.s, sharename, 0, mapping)
	if err != nil {
		return nil, err
	}
	return &Share{treeConn: tc, ctx: context.Background(), mapping: mapping}, nil
}

// warnIfNoDFSCap emits a one-line diagnostic (rule 30) when DFS following
// was requested but the server advertised no DFS capability, so callers
// are not left wondering why referrals are never followed.
func (c *Session) warnIfNoDFSCap(r *dfsResolver) {
	if !c.supportsDFS() {
		r.logf("smb2 dfs: EnableDFS set but server %s advertised no DFS capability; referral following is inert", c.serverName())
	}
}

// isIPCShare reports whether sharename targets the inter-process
// communication share. DFS routing must never attach to \IPC$ (the DFS
// referral IOCTL itself mounts \IPC$, which would otherwise recurse).
func isIPCShare(sharename string) bool {
	return strings.HasSuffix(strings.ToUpper(strings.TrimRight(sharename, `\`)), `\IPC$`)
}

// isPathNotCovered reports whether err is STATUS_PATH_NOT_COVERED — the
// mid-operation signal that a path crossed a DFS link.
func isPathNotCovered(err error) bool {
	var re *ResponseError
	return errors.As(err, &re) && erref.NtStatus(re.Code) == erref.STATUS_PATH_NOT_COVERED
}

// isDFSResolvable reports whether a failed tree connect (Case A) is a
// DFS-shaped error worth attempting referral resolution for.
func isDFSResolvable(err error) bool {
	var re *ResponseError
	if !errors.As(err, &re) {
		return false
	}
	switch erref.NtStatus(re.Code) {
	case erref.STATUS_BAD_NETWORK_NAME,
		erref.STATUS_PATH_NOT_COVERED,
		erref.STATUS_DFS_UNAVAILABLE:
		return true
	}
	return false
}
