package storage

import (
	"context"
	"database/sql"
	"net"

	"github.com/jbrekelmans/go-sql-ip-management/cidr"
)

// Record is a range of IP addresses that may or may not be allocated.
// The range of IP addresses is represented using CIDR notation.
// As such, all IP addresses in the range have a common prefix.
// For example, CIDR notation 192.168.128.0/17 specifies the range
// 192.168.128.0 to 192.168.255.255 (inclusive).
type Record struct {
	PoolID int
	// RequestID is a human-readable identifier of the object this range is allocated to.
	// Empty if this range is free (not allocated to any object).
	RequestID string
	// C is the CIDR notation for the range of IP addresses.
	C cidr.CIDR
}

// DeepCopy returns a deep copy of r.
func (r Record) DeepCopy() Record {
	deepCopy := r
	deepCopy.C.IP = append(net.IP(nil), deepCopy.C.IP...)
	return deepCopy
}

type Storage interface {
	// BeginTransaction starts a transaction to read/write to Storage.
	// See https://en.wikipedia.org/wiki/Isolation_(database_systems)#Isolation_levels
	// for the definition of txOpts.IsolationLevel.
	// Callers must call Commit or Rollback on the returned transaction (unless BeginTransaction returns an error).
	// If the context is canceled the transaction is rolled back.
	BeginTransaction(ctx context.Context, txOpts *sql.TxOptions) (Transaction, error)
}

type Transaction interface {
	// Commit the transaction.
	Commit() error

	// Delete deletes the specified record.
	Delete(ctx context.Context, poolID int, c cidr.CIDR) error

	// FindAllocated finds the record allocated to the object
	// identified by requestID.
	// If no such record exists then returns nil.
	// If requestID is empty then returns an error.
	// Since no two different records can have equal requestID,
	// there is at most one such record.
	FindAllocated(ctx context.Context, poolID int, requestID string) (*Record, error)

	// FindSmallestFree finds records that:
	// 1. are not allocated to any object;
	// 2. have a range of IP addresses of at least a certain size; -and
	// 3. are the records with the smallest range that satisfy 1 and 2.
	// If no such records exist then returns nil.
	// Otherwise, returns an arbitrary such record.
	//
	// Recall that ranges of IP addresses are represented using CIDR notation,
	// and all IP addresses in a range have a common prefix.
	// For example, CIDR notation 192.168.128.0/17 specifies the range
	// 192.168.128.0 to 192.168.255.255 (inclusive).
	//
	// The minimum size of the range of IP addresses is specified as prefixBits,
	// which is the binary length of the (longest) common prefix of the range.
	// This is equivalent to the number to the right of the slash in CIDR
	// notation. For example, the size of 192.168.128.0/17 has prefixBits = 17.
	FindSmallestFree(ctx context.Context, poolID, prefixBits int) (*Record, error)

	Get(ctx context.Context, poolID int, c cidr.CIDR) (*Record, error)

	// InsertMany inserts multiple records.
	InsertMany(ctx context.Context, records []Record) error

	// Rollback the transaction.
	Rollback() error

	// Update updates an existing record.
	Update(ctx context.Context, record Record) error
}
