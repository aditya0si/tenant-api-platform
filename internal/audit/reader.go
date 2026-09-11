package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// PageSize bounds a listing.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// Reader queries the trail.
//
// It is separate from Write — which takes a transaction — because reading is not part of any
// effect and needs no transaction of its own beyond the identity settings.
type Reader struct {
	pool *pgxpool.Pool
}

// NewReader builds a reader.
func NewReader(pool *pgxpool.Pool) *Reader { return &Reader{pool: pool} }

// Result is one page of entries.
type Result struct {
	Entries []Record
	Next    *cursor.Position
}

// List returns one page of a tenant's entries, newest first, keyset-paginated.
//
// # Why keyset rather than offset
//
// The same reasoning as the projects listing: an append-only table is written continuously, so
// rows inserted between two requests shift every offset and an offset-based page 2 can repeat
// or skip entries the client has already seen. `(at, id)` is immutable and monotonic, so a
// cursor into it stays correct no matter how much is appended meanwhile.
//
// # Why the id is part of the position
//
// `at` is the database's `now()`, which is fixed for the whole of a transaction. Two entries
// written in one transaction therefore share a timestamp exactly, and a cursor on the time
// alone would skip or repeat them. The id breaks the tie, and UUIDv7 sorts by creation, so
// within one timestamp it orders the way a reader expects.
func (r *Reader) List(ctx context.Context, auth tenant.Authorized, after *cursor.Position, limit int) (Result, error) {
	if !auth.Valid() {
		return Result{}, apperr.ErrNoScope
	}
	limit = normalizePageSize(limit)

	var out []Record
	err := withReaderTx(ctx, r.pool, auth, func(tx pgx.Tx) error {
		// afterTime is *time.Time rather than *interface{}: pgx encodes *time.Time natively
		// for a nullable timestamptz, whereas a pointer-to-interface has no registered codec
		// and fails at encode time.
		var afterTime *time.Time
		var afterID uuid.UUID
		if after != nil {
			t := after.Time
			afterTime = &t
			afterID = after.ID
		}

		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, actor_id, actor_kind, action, resource, resource_id,
			       before, after, request_id, at
			  FROM audit_log
			 WHERE tenant_id = $1
			   AND ($2::timestamptz IS NULL OR (at, id) < ($2::timestamptz, $3::uuid))
			 ORDER BY at DESC, id DESC
			 LIMIT $4`,
			auth.Scope().ID(), afterTime, afterID, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var rec Record
			if err := rows.Scan(&rec.ID, &rec.TenantID, &rec.ActorID, &rec.ActorKind, &rec.Action,
				&rec.Resource, &rec.ResourceID, &rec.Before, &rec.After, &rec.RequestID, &rec.At); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	if err != nil {
		return Result{}, fmt.Errorf("list audit entries: %w", err)
	}

	res := Result{Entries: out}
	if len(out) > limit {
		// One extra row was fetched to decide whether a next page exists, then dropped. The
		// cursor points at the last row the client actually received, so the extra row is
		// simply fetched again rather than sitting in a page of its own.
		res.Entries = out[:limit]
		last := out[limit-1]
		res.Next = &cursor.Position{Time: last.At, ID: last.ID}
	}
	return res, nil
}

// Binding describes the query a pagination cursor belongs to, so a cursor minted for one
// listing cannot be replayed against another.
func Binding(auth tenant.Authorized) cursor.Binding {
	return cursor.Binding{
		TenantID: auth.Scope().ID(),
		Resource: "audit",
		Filter:   "all",
	}
}

// withReaderTx runs fn with the caller's tenant identity applied.
//
// It delegates to the platform helper rather than re-implementing the GUC plumbing: the
// setting names must have exactly one definition, and a second copy here is precisely how the
// two would drift until a policy silently stopped matching.
func withReaderTx(ctx context.Context, pool *pgxpool.Pool, auth tenant.Authorized, fn func(pgx.Tx) error) error {
	return db.WithIdentityTx(ctx, pool, auth.Identity(), fn)
}

// normalizePageSize clamps a requested page size into range.
func normalizePageSize(n int) int {
	switch {
	case n <= 0:
		return DefaultPageSize
	case n > MaxPageSize:
		return MaxPageSize
	default:
		return n
	}
}
