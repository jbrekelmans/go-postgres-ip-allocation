package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/jbrekelmans/go-sql-ip-management/cidr"
	"github.com/jbrekelmans/go-sql-ip-management/storage"
)

type SQLStorage struct {
	db *sql.DB
}

var _ storage.Storage = (*SQLStorage)(nil)

func NewSQLStorage(db *sql.DB) *SQLStorage {
	return &SQLStorage{
		db: db,
	}
}

func (s *SQLStorage) BeginTransaction(ctx context.Context, txOpts *sql.TxOptions) (storage.Transaction, error) {
	tx, err := s.db.BeginTx(ctx, txOpts)
	if err != nil {
		return nil, err
	}
	return &txWrapper{
		tx: tx,
	}, nil
}

type txWrapper struct {
	tx *sql.Tx
}

var _ storage.Transaction = (*txWrapper)(nil)

func (t *txWrapper) Commit() error {
	return t.tx.Commit()
}

func (t *txWrapper) Delete(ctx context.Context, poolID int, c cidr.CIDR) error {
	return t.execContext(ctx, 1, `DELETE FROM public.ip_range WHERE pool_id=$1 AND c=$2`, poolID, c.String())
}

func (t *txWrapper) execContext(ctx context.Context, expectedRowsAffected int, query string, args ...any) error {
	log.Debug().Str("q", query).Any("qv", args).Msg("executing statement")
	result, err := t.tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	actualRowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if expectedRowsAffected != int(actualRowsAffected) {
		return fmt.Errorf(`statement affected unexpected number of rows %d (expected %d)`, actualRowsAffected, expectedRowsAffected)
	}
	return nil
}

func (t *txWrapper) FindAllocated(ctx context.Context, poolID int, requestID string) (*storage.Record, error) {
	if requestID == "" {
		return nil, fmt.Errorf("requestID must not be empty")
	}
	row := t.queryRow(ctx, `SELECT c FROM public.ip_range WHERE pool_id=$1 AND request_id=$2`, poolID, requestID)
	record := &storage.Record{RequestID: requestID, PoolID: poolID}
	err := row.Scan(&record.C)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, nil
	}
	return record, nil
}

func (t *txWrapper) FindSmallestFree(ctx context.Context, poolID, prefixBits int) (*storage.Record, error) {
	row := t.queryRow(ctx,
		`SELECT c
FROM public.ip_range
WHERE request_id IS NULL AND masklen(c) <= (
	SELECT MAX(masklen(c))
	FROM public.ip_range
	WHERE request_id IS NULL AND masklen(c) <= $1
	)
ORDER BY masklen(c) DESC
LIMIT 1`, prefixBits)
	record := &storage.Record{PoolID: poolID}
	err := row.Scan(&record.C)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, nil
	}
	return record, nil
}

func (t *txWrapper) Get(ctx context.Context, poolID int, c cidr.CIDR) (*storage.Record, error) {
	row := t.queryRow(ctx, `SELECT request_id FROM public.ip_range WHERE pool_id=$1 AND c=$2`, poolID, c.String())
	record := &storage.Record{PoolID: poolID, C: c}
	var requestID *string
	err := row.Scan(&requestID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, nil
	}
	if requestID != nil {
		record.RequestID = *requestID
	}
	return record, nil
}

func (t *txWrapper) InsertMany(ctx context.Context, records []storage.Record) error {
	if len(records) == 0 {
		return nil
	}
	var statementBuilder bytes.Buffer
	statementBuilder.WriteString(`INSERT INTO public.ip_range(pool_id,c,request_id) VALUES `)
	statementArgs := make([]any, 0, len(records)*2+2)
	placeholderCounter := 1
	nextPlaceholder := func() string {
		p := fmt.Sprintf("$%d", placeholderCounter)
		placeholderCounter++
		return p
	}
	intPlaceholders := make(map[int]string)
	var nilPlaceholder string
	addStatementArg := func(a any) {
		switch aTyped := a.(type) {
		case nil:
			if nilPlaceholder == "" {
				nilPlaceholder = nextPlaceholder()
				statementArgs = append(statementArgs, nil)
			}
			statementBuilder.WriteString(nilPlaceholder)
		case int:
			p, ok := intPlaceholders[aTyped]
			if !ok {
				p = nextPlaceholder()
				intPlaceholders[aTyped] = p
				statementArgs = append(statementArgs, aTyped)
			}
			statementBuilder.WriteString(p)
		default:
			// TODO use nil placeholder if value is another type of nil
			statementBuilder.WriteString(nextPlaceholder())
			statementArgs = append(statementArgs, a)
		}
	}
	for _, record := range records {
		statementBuilder.WriteByte('(')
		addStatementArg(record.PoolID)
		statementBuilder.WriteByte(',')
		addStatementArg(record.C.String())
		statementBuilder.WriteByte(',')
		addStatementArg(emptyStringToNil(record.RequestID))
		statementBuilder.WriteString("),")
	}
	statementBytes := statementBuilder.Bytes()
	statementBytes = statementBytes[:len(statementBytes)-1]
	statementStr := string(statementBytes)
	return t.execContext(ctx, len(records), statementStr, statementArgs...)
}

func (t *txWrapper) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	log.Debug().Str("q", query).Any("qv", args).Msg("doing query")
	return t.tx.QueryRowContext(ctx, query, args...)
}

func (t *txWrapper) Rollback() error {
	return t.tx.Rollback()
}

func (t *txWrapper) Update(ctx context.Context, record storage.Record) error {
	return t.execContext(ctx, 1,
		`UPDATE public.ip_range SET request_id=$1 WHERE pool_id=$2 AND c=$3`,
		emptyStringToNil(record.RequestID), record.PoolID, record.C.String())
}

func emptyStringToNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}
